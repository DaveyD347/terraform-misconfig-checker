"""A small, dependency-free HCL2 parser.

It covers the native HCL syntax that Terraform configurations use in practice:
blocks, attributes, every expression form (literals, templates and heredocs,
tuples, objects, function calls, references, splats, conditionals, operators
and ``for`` expressions) and all three comment styles. Every node keeps the
line it started on, so findings can point at the exact attribute.

Comments are collected per line so that inline suppressions
(``# tfcheck:ignore=...``) can be matched to resources.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class HCLError(Exception):
    def __init__(self, message: str, line: int, filename: str = "<string>"):
        super().__init__(f"{filename}:{line}: {message}")
        self.message = message
        self.line = line
        self.filename = filename


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass
class Node:
    line: int


@dataclass
class Literal(Node):
    value: object


@dataclass
class Directive(Node):
    """A ``%{ ... }`` template directive. Evaluates to an unknown value."""


@dataclass
class Template(Node):
    parts: list  # str | Node


@dataclass
class Variable(Node):
    name: str


@dataclass
class GetAttr(Node):
    obj: Node
    name: str


@dataclass
class Index(Node):
    obj: Node
    key: Node


@dataclass
class Splat(Node):
    obj: Node
    steps: list  # ("attr", name) | ("index", Node)


@dataclass
class Call(Node):
    name: str
    args: list
    expand_final: bool = False


@dataclass
class TupleExpr(Node):
    items: list


@dataclass
class ObjectExpr(Node):
    items: list  # (key Node, value Node)


@dataclass
class Conditional(Node):
    cond: Node
    true: Node
    false: Node


@dataclass
class BinaryOp(Node):
    op: str
    left: Node
    right: Node


@dataclass
class UnaryOp(Node):
    op: str
    operand: Node


@dataclass
class ForExpr(Node):
    key_var: str | None
    value_var: str
    collection: Node
    key_expr: Node | None  # set for object results
    value_expr: Node
    cond: Node | None
    grouping: bool = False


@dataclass
class Attribute:
    name: str
    expr: Node
    line: int


@dataclass
class Block:
    type: str
    labels: list[str]
    body: Body
    line: int
    end_line: int


@dataclass
class Body:
    attributes: dict[str, Attribute] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


@dataclass
class File:
    body: Body
    comments: dict[int, list[str]]
    filename: str


BodyItem = Attribute | Block

# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

IDENT, NUMBER, STRING, PUNCT, NEWLINE, EOF = "IDENT", "NUMBER", "STRING", "PUNCT", "NEWLINE", "EOF"

_PUNCT3 = ("...",)
_PUNCT2 = ("==", "!=", "<=", ">=", "&&", "||", "=>", "::")
_PUNCT1 = "{}[]()=,.:?!<>+-*/%"


@dataclass
class Token:
    kind: str
    value: object
    line: int


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch in "_-"


class Lexer:
    def __init__(self, src: str, filename: str = "<string>", line: int = 1):
        self.src = src
        self.pos = 0
        self.line = line
        self.filename = filename
        self.comments: dict[int, list[str]] = {}

    def error(self, msg: str) -> HCLError:
        return HCLError(msg, self.line, self.filename)

    # -- helpers -----------------------------------------------------------
    def _peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def _add_comment(self, line: int, text: str) -> None:
        self.comments.setdefault(line, []).append(text)

    def tokenize(self) -> list[Token]:
        tokens = []
        while True:
            tok = self.next_token()
            tokens.append(tok)
            if tok.kind == EOF:
                return tokens

    def next_token(self) -> Token:
        src = self.src
        while True:
            ch = self._peek()
            if ch == "":
                return Token(EOF, None, self.line)
            if ch in " \t\r":
                self.pos += 1
                continue
            if ch == "\\" and self._peek(1) == "\n":  # line continuation (rare)
                self.pos += 2
                self.line += 1
                continue
            if ch == "#" or (ch == "/" and self._peek(1) == "/"):
                start = self.pos
                end = src.find("\n", start)
                end = len(src) if end == -1 else end
                self._add_comment(self.line, src[start:end])
                self.pos = end
                continue
            if ch == "/" and self._peek(1) == "*":
                end = src.find("*/", self.pos + 2)
                if end == -1:
                    raise self.error("unterminated block comment")
                text = src[self.pos : end + 2]
                self._add_comment(self.line, text)
                self.line += text.count("\n")
                self.pos = end + 2
                continue
            break

        line = self.line
        if ch == "\n":
            self.pos += 1
            self.line += 1
            return Token(NEWLINE, None, line)
        if _is_ident_start(ch):
            start = self.pos
            while self.pos < len(src) and _is_ident_char(src[self.pos]):
                self.pos += 1
            return Token(IDENT, src[start : self.pos], line)
        if ch.isdigit():
            return self._number()
        if ch == '"':
            self.pos += 1
            node = self.template(terminator='"')
            return Token(STRING, node, line)
        if ch == "<" and self._peek(1) == "<" and (_is_ident_start(self._peek(2)) or self._peek(2) == "-"):
            return self._heredoc()
        for p in _PUNCT3 + _PUNCT2:
            if src.startswith(p, self.pos):
                self.pos += len(p)
                return Token(PUNCT, p, line)
        if ch in _PUNCT1:
            self.pos += 1
            return Token(PUNCT, ch, line)
        raise self.error(f"unexpected character {ch!r}")

    def _number(self) -> Token:
        start, line = self.pos, self.line
        while self._peek().isdigit():
            self.pos += 1
        is_float = False
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            self.pos += 1
            while self._peek().isdigit():
                self.pos += 1
        if self._peek() in ("e", "E") and (
            self._peek(1).isdigit() or (self._peek(1) in "+-" and self._peek(2).isdigit())
        ):
            is_float = True
            self.pos += 2
            while self._peek().isdigit():
                self.pos += 1
        text = self.src[start : self.pos]
        return Token(NUMBER, float(text) if is_float else int(text), line)

    def _heredoc(self) -> Token:
        line = self.line
        self.pos += 2
        strip = False
        if self._peek() == "-":
            strip = True
            self.pos += 1
        start = self.pos
        while _is_ident_char(self._peek()):
            self.pos += 1
        marker = self.src[start : self.pos]
        nl = self.src.find("\n", self.pos)
        if nl == -1 or self.src[self.pos : nl].strip():
            raise self.error("heredoc marker must be followed by a newline")
        self.pos = nl + 1
        self.line += 1
        body_lines = []
        content_line = self.line
        while True:
            if self.pos >= len(self.src):
                raise HCLError(f"unterminated heredoc {marker}", line, self.filename)
            nl = self.src.find("\n", self.pos)
            end = len(self.src) if nl == -1 else nl
            text = self.src[self.pos : end]
            if text.strip() == marker:
                self.pos = end  # leave the newline: it terminates the attribute
                break
            self.pos = end + 1 if nl != -1 else end
            self.line += 1
            body_lines.append(text + "\n")
        if strip:
            indents = [len(t) - len(t.lstrip(" \t")) for t in body_lines if t.strip()]
            cut = min(indents) if indents else 0
            body_lines = [t[cut:] if t.strip() else t.lstrip(" \t") for t in body_lines]
        sub = Lexer("".join(body_lines), self.filename, content_line)
        node = sub.template(terminator=None, heredoc=True)
        for ln, texts in sub.comments.items():
            for t in texts:
                self._add_comment(ln, t)
        return Token(STRING, node, line)

    # -- templates ---------------------------------------------------------
    def template(self, terminator: str | None, heredoc: bool = False) -> Template:
        """Read template content up to ``terminator`` (or end of input)."""
        start_line = self.line
        parts: list = []
        buf: list[str] = []
        while True:
            ch = self._peek()
            if ch == "":
                if terminator is not None:
                    raise HCLError("unterminated string", start_line, self.filename)
                break
            if terminator is not None and ch == terminator:
                self.pos += 1
                break
            if ch == "\n":
                if not heredoc:
                    raise HCLError("newline in quoted string", self.line, self.filename)
                buf.append(ch)
                self.pos += 1
                self.line += 1
                continue
            if ch == "\\" and not heredoc:
                buf.append(self._escape())
                continue
            if ch in "$%" and self._peek(1) == ch and self._peek(2) == "{":
                buf.append(ch + "{")
                self.pos += 3
                continue
            if ch in "$%" and self._peek(1) == "{":
                if buf:
                    parts.append("".join(buf))
                    buf = []
                line = self.line
                self.pos += 2
                if self._peek() == "~":
                    self.pos += 1
                tokens = self._tokens_until_close_brace()
                if tokens and tokens[-1].kind == PUNCT and tokens[-1].value == "~":
                    tokens.pop()
                if ch == "%":
                    parts.append(Directive(line))
                else:
                    tokens.append(Token(EOF, None, self.line))
                    p = Parser(tokens, self.filename)
                    p.nl_skip = 1
                    expr = p.expression()
                    p.skip_newlines()
                    p.expect_kind(EOF)
                    parts.append(expr)
                continue
            buf.append(ch)
            self.pos += 1
        if buf:
            parts.append("".join(buf))
        return Template(start_line, parts)

    def _escape(self) -> str:
        nxt = self._peek(1)
        simple = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
        if nxt in simple:
            self.pos += 2
            return simple[nxt]
        if nxt in ("u", "U"):
            width = 4 if nxt == "u" else 8
            digits = self.src[self.pos + 2 : self.pos + 2 + width]
            try:
                value = chr(int(digits, 16))
            except ValueError:
                raise self.error("invalid unicode escape") from None
            self.pos += 2 + width
            return value
        raise self.error(f"invalid escape sequence \\{nxt}")

    def _tokens_until_close_brace(self) -> list[Token]:
        depth = 0
        tokens = []
        while True:
            tok = self.next_token()
            if tok.kind == EOF:
                raise self.error("unterminated template interpolation")
            if tok.kind == PUNCT and tok.value == "{":
                depth += 1
            elif tok.kind == PUNCT and tok.value == "}":
                if depth == 0:
                    return tokens
                depth -= 1
            tokens.append(tok)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_BINARY_PRECEDENCE = [
    ("||",),
    ("&&",),
    ("==", "!="),
    ("<", ">", "<=", ">="),
    ("+", "-"),
    ("*", "/", "%"),
]


class Parser:
    def __init__(self, tokens: list[Token], filename: str = "<string>"):
        self.tokens = tokens
        self.i = 0
        self.filename = filename
        self.nl_skip = 0  # >0 while inside (), [] or {} expressions

    # -- token helpers -----------------------------------------------------
    def _raw(self, offset: int = 0) -> Token:
        j = min(self.i + offset, len(self.tokens) - 1)
        return self.tokens[j]

    def peek(self) -> Token:
        if self.nl_skip:
            self.skip_newlines()
        return self._raw()

    def advance(self) -> Token:
        tok = self.peek()
        self.i += 1
        return tok

    def skip_newlines(self) -> None:
        while self._raw().kind == NEWLINE:
            self.i += 1

    def is_punct(self, value: str) -> bool:
        tok = self.peek()
        return tok.kind == PUNCT and tok.value == value

    def accept(self, value: str) -> bool:
        if self.is_punct(value):
            self.i += 1
            return True
        return False

    def expect(self, value: str) -> Token:
        tok = self.peek()
        if tok.kind != PUNCT or tok.value != value:
            raise self.error(f"expected {value!r}, found {self._describe(tok)}", tok)
        self.i += 1
        return tok

    def expect_kind(self, kind: str) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            raise self.error(f"expected {kind.lower()}, found {self._describe(tok)}", tok)
        self.i += 1
        return tok

    def error(self, msg: str, tok: Token | None = None) -> HCLError:
        tok = tok or self._raw()
        return HCLError(msg, tok.line, self.filename)

    @staticmethod
    def _describe(tok: Token) -> str:
        if tok.kind == EOF:
            return "end of file"
        if tok.kind == NEWLINE:
            return "newline"
        if tok.kind == STRING:
            return "string"
        return repr(tok.value)

    # -- structure ---------------------------------------------------------
    def body(self, closing: str | None) -> Body:
        body = Body()
        while True:
            self.skip_newlines()
            tok = self._raw()
            if closing is None and tok.kind == EOF:
                return body
            if closing is not None and tok.kind == PUNCT and tok.value == closing:
                return body
            if tok.kind != IDENT:
                raise self.error(f"expected attribute or block name, found {self._describe(tok)}", tok)
            self.i += 1
            name = tok.value
            nxt = self._raw()
            if nxt.kind == PUNCT and nxt.value == "=":
                self.i += 1
                expr = self.expression()
                end = self._raw()
                if end.kind not in (NEWLINE, EOF) and not (end.kind == PUNCT and end.value == closing):
                    raise self.error(f"expected newline after attribute, found {self._describe(end)}", end)
                if name in body.attributes:
                    raise self.error(f"duplicate attribute {name!r}", tok)
                body.attributes[name] = Attribute(name, expr, tok.line)
                continue
            labels = []
            while True:
                nxt = self._raw()
                if nxt.kind == STRING:
                    labels.append(_static_string(nxt.value, self, nxt))
                    self.i += 1
                elif nxt.kind == IDENT:
                    labels.append(nxt.value)
                    self.i += 1
                else:
                    break
            if not (nxt.kind == PUNCT and nxt.value == "{"):
                raise self.error(f"expected '=' or '{{' after {name!r}, found {self._describe(nxt)}", nxt)
            self.i += 1
            inner = self.body("}")
            close = self._raw()
            self.i += 1
            body.blocks.append(Block(name, labels, inner, tok.line, close.line))

    # -- expressions -------------------------------------------------------
    def expression(self) -> Node:
        cond = self._binary(0)
        if self.is_punct("?"):
            self.i += 1
            true = self.expression()
            self.expect(":")
            false = self.expression()
            return Conditional(cond.line, cond, true, false)
        return cond

    def _binary(self, level: int) -> Node:
        if level == len(_BINARY_PRECEDENCE):
            return self._unary()
        left = self._binary(level + 1)
        ops = _BINARY_PRECEDENCE[level]
        while True:
            tok = self.peek()
            if tok.kind == PUNCT and tok.value in ops:
                self.i += 1
                right = self._binary(level + 1)
                left = BinaryOp(left.line, tok.value, left, right)
            else:
                return left

    def _unary(self) -> Node:
        tok = self.peek()
        if tok.kind == PUNCT and tok.value in ("!", "-"):
            self.i += 1
            operand = self._unary()
            if tok.value == "-" and isinstance(operand, Literal) and isinstance(operand.value, (int, float)):
                return Literal(tok.line, -operand.value)
            return UnaryOp(tok.line, tok.value, operand)
        return self._postfix(self._primary())

    def _postfix(self, node: Node) -> Node:
        while True:
            tok = self._raw() if not self.nl_skip else self.peek()
            if tok.kind != PUNCT:
                return node
            if tok.value == ".":
                nxt = self._raw(1)
                if nxt.kind == PUNCT and nxt.value == "*":
                    self.i += 2
                    node = Splat(node.line, node, self._splat_steps())
                elif nxt.kind == IDENT:
                    self.i += 2
                    node = GetAttr(node.line, node, nxt.value)
                elif nxt.kind == NUMBER and isinstance(nxt.value, int):
                    self.i += 2
                    node = Index(node.line, node, Literal(nxt.line, nxt.value))
                else:
                    raise self.error("expected attribute name after '.'", nxt)
            elif tok.value == "[":
                nxt = self._raw(1)
                if nxt.kind == PUNCT and nxt.value == "*" and self._raw(2).value == "]":
                    self.i += 3
                    node = Splat(node.line, node, self._splat_steps(full=True))
                else:
                    self.i += 1
                    self.nl_skip += 1
                    try:
                        key = self.expression()
                        self.expect("]")
                    finally:
                        self.nl_skip -= 1
                    node = Index(node.line, node, key)
            else:
                return node

    def _splat_steps(self, full: bool = False) -> list:
        steps = []
        while True:
            tok = self._raw()
            if tok.kind == PUNCT and tok.value == "." and self._raw(1).kind == IDENT:
                steps.append(("attr", self._raw(1).value))
                self.i += 2
            elif full and tok.kind == PUNCT and tok.value == "[":
                self.i += 1
                self.nl_skip += 1
                try:
                    key = self.expression()
                    self.expect("]")
                finally:
                    self.nl_skip -= 1
                steps.append(("index", key))
            else:
                return steps

    def _primary(self) -> Node:
        tok = self.peek()
        line = tok.line
        if tok.kind == NUMBER:
            self.i += 1
            return Literal(line, tok.value)
        if tok.kind == STRING:
            self.i += 1
            return tok.value
        if tok.kind == IDENT:
            self.i += 1
            name = tok.value
            if name == "true":
                return Literal(line, True)
            if name == "false":
                return Literal(line, False)
            if name == "null":
                return Literal(line, None)
            # provider-defined functions: provider::name::func(...)
            while self._raw().kind == PUNCT and self._raw().value == "::" and self._raw(1).kind == IDENT:
                name += "::" + self._raw(1).value
                self.i += 2
            nxt = self._raw()
            if nxt.kind == PUNCT and nxt.value == "(":
                self.i += 1
                return self._call(name, line)
            return Variable(line, name)
        if tok.kind == PUNCT:
            if tok.value == "(":
                self.i += 1
                self.nl_skip += 1
                try:
                    expr = self.expression()
                    self.expect(")")
                finally:
                    self.nl_skip -= 1
                return expr
            if tok.value == "[":
                self.i += 1
                return self._tuple(line)
            if tok.value == "{":
                self.i += 1
                return self._object(line)
        raise self.error(f"expected expression, found {self._describe(tok)}", tok)

    def _call(self, name: str, line: int) -> Node:
        args = []
        expand = False
        self.nl_skip += 1
        try:
            while not self.is_punct(")"):
                args.append(self.expression())
                if self.accept("..."):
                    expand = True
                if not self.accept(","):
                    break
            self.expect(")")
        finally:
            self.nl_skip -= 1
        return Call(line, name, args, expand)

    def _is_for(self) -> bool:
        tok = self.peek()
        return tok.kind == IDENT and tok.value == "for" and self._raw(1).kind == IDENT

    def _for_header(self):
        self.i += 1  # 'for'
        first = self.expect_kind(IDENT).value
        second = None
        if self.accept(","):
            second = self.expect_kind(IDENT).value
        tok = self.expect_kind(IDENT)
        if tok.value != "in":
            raise self.error("expected 'in' in for expression", tok)
        collection = self.expression()
        self.expect(":")
        if second is None:
            return None, first, collection
        return first, second, collection

    def _tuple(self, line: int) -> Node:
        self.nl_skip += 1
        try:
            if self._is_for():
                key_var, value_var, coll = self._for_header()
                value = self.expression()
                cond = None
                tok = self.peek()
                if tok.kind == IDENT and tok.value == "if":
                    self.i += 1
                    cond = self.expression()
                self.expect("]")
                return ForExpr(line, key_var, value_var, coll, None, value, cond)
            items = []
            while not self.is_punct("]"):
                items.append(self.expression())
                if not self.accept(","):
                    break
            self.expect("]")
            return TupleExpr(line, items)
        finally:
            self.nl_skip -= 1

    def _object(self, line: int) -> Node:
        self.nl_skip += 1
        try:
            if self._is_for():
                key_var, value_var, coll = self._for_header()
                key = self.expression()
                self.expect("=>")
                value = self.expression()
                grouping = self.accept("...")
                cond = None
                tok = self.peek()
                if tok.kind == IDENT and tok.value == "if":
                    self.i += 1
                    cond = self.expression()
                self.expect("}")
                return ForExpr(line, key_var, value_var, coll, key, value, cond, grouping)
            items = []
            while not self.is_punct("}"):
                key = self.expression()
                if isinstance(key, Variable):
                    key = Literal(key.line, key.name)
                if not (self.accept("=") or self.accept(":")):
                    raise self.error("expected '=' or ':' after object key")
                value = self.expression()
                items.append((key, value))
                self.accept(",")
            self.expect("}")
            return ObjectExpr(line, items)
        finally:
            self.nl_skip -= 1


def _static_string(tmpl: Template, parser: Parser, tok: Token) -> str:
    if all(isinstance(p, str) for p in tmpl.parts):
        return "".join(tmpl.parts)
    raise parser.error("block labels must be literal strings", tok)


def parse(src: str, filename: str = "<string>") -> File:
    """Parse HCL source text into a :class:`File`."""
    if src.startswith("﻿"):
        src = src[1:]
    lexer = Lexer(src, filename)
    tokens = lexer.tokenize()
    parser = Parser(tokens, filename)
    body = parser.body(None)
    return File(body, lexer.comments, filename)


def parse_expression(src: str) -> Node:
    lexer = Lexer(src)
    parser = Parser(lexer.tokenize())
    expr = parser.expression()
    parser.skip_newlines()
    parser.expect_kind(EOF)
    return expr
