"""Partial evaluation of HCL expressions.

Static analysis never has the full picture: resource attributes that are only
known after apply, data sources, module outputs and ``count``/``each`` values
are all unknown. The evaluator resolves what it can (literals, variables with
defaults or tfvars values, locals, common functions) and returns
:data:`UNKNOWN` for the rest. References to other resources come back as
:class:`Ref` objects so rules can follow links between resources, such as a
public access block pointing at its bucket.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable

from . import hcl


class Unknown:
    """A value that cannot be known without running Terraform."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:  # pragma: no cover - guard against accidental truthiness
        raise TypeError("truth value of an unknown value is undefined")


UNKNOWN = Unknown()


class Ref:
    """A reference to another object in the configuration, e.g. ``aws_s3_bucket.logs.id``."""

    __slots__ = ("address",)

    def __init__(self, address: str):
        self.address = address

    def attr(self, name: str) -> Ref:
        return Ref(f"{self.address}.{name}")

    def refers_to(self, base_address: str) -> bool:
        return self.address == base_address or self.address.startswith(base_address + ".")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Ref) and other.address == self.address

    def __hash__(self) -> int:
        return hash(self.address)

    def __repr__(self) -> str:
        return f"Ref({self.address!r})"


class EncodedJSON:
    """Result of ``jsonencode()`` on a value that is only partly known.

    Policies are usually written with ``jsonencode`` and often interpolate
    ARNs of other resources. Keeping the decoded structure lets IAM rules
    inspect the statements even though the final string is not known.
    """

    __slots__ = ("data",)

    def __init__(self, data):
        self.data = data

    def __repr__(self) -> str:
        return f"EncodedJSON({self.data!r})"


def is_unknown(value) -> bool:
    return value is UNKNOWN or isinstance(value, (Ref, EncodedJSON))


def contains_unknown(value) -> bool:
    if is_unknown(value):
        return True
    if isinstance(value, dict):
        return any(contains_unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_unknown(v) for v in value)
    return False


class EvalError(Exception):
    pass


class LazyNamespace:
    """``local.*``: each local is evaluated the first time it is used."""

    def __init__(self, exprs: dict[str, hcl.Node], evaluator: Evaluator):
        self.exprs = exprs
        self.evaluator = evaluator
        self.cache: dict[str, object] = {}
        self.active: set[str] = set()

    def get(self, name: str):
        if name in self.cache:
            return self.cache[name]
        if name not in self.exprs or name in self.active:
            return UNKNOWN
        self.active.add(name)
        try:
            value = self.evaluator.eval(self.exprs[name])
        finally:
            self.active.discard(name)
        self.cache[name] = value
        return value


_UNKNOWN_ROOTS = {"module", "each", "count", "path", "terraform", "self", "provider"}


class Evaluator:
    def __init__(self, variables: dict | None = None, locals_: dict[str, hcl.Node] | None = None):
        self.variables = variables or {}
        self.locals = LazyNamespace(locals_ or {}, self)
        self.scopes: list[dict] = []

    def with_scope(self, bindings: dict) -> Evaluator:
        child = Evaluator.__new__(Evaluator)
        child.variables = self.variables
        child.locals = self.locals
        child.scopes = self.scopes + [bindings]
        return child

    # ------------------------------------------------------------------
    def eval(self, node: hcl.Node):
        try:
            return self._eval(node)
        except (EvalError, TypeError, ValueError, KeyError, IndexError, ZeroDivisionError, RecursionError):
            return UNKNOWN

    def _eval(self, node: hcl.Node):
        method = getattr(self, "_eval_" + type(node).__name__)
        return method(node)

    def _eval_Literal(self, node: hcl.Literal):
        return node.value

    def _eval_Directive(self, node):
        return UNKNOWN

    def _eval_Template(self, node: hcl.Template):
        parts = node.parts
        if len(parts) == 1 and isinstance(parts[0], hcl.Node):
            return self._eval(parts[0])
        out = []
        for part in parts:
            if isinstance(part, str):
                out.append(part)
                continue
            value = self._eval(part)
            if is_unknown(value) or isinstance(value, (dict, list)):
                return UNKNOWN
            out.append(_to_string(value))
        return "".join(out)

    def _eval_Variable(self, node: hcl.Variable):
        name = node.name
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        if name == "var":
            return self.variables
        if name == "local":
            return self.locals
        if name == "data":
            return Ref("data")
        if name in _UNKNOWN_ROOTS:
            return UNKNOWN
        return Ref(name)

    def _eval_GetAttr(self, node: hcl.GetAttr):
        base = self._eval(node.obj)
        return _get_attr(base, node.name)

    def _eval_Index(self, node: hcl.Index):
        base = self._eval(node.obj)
        if isinstance(base, Ref):
            return base  # aws_instance.web[0].id still refers to aws_instance.web
        key = self._eval(node.key)
        if base is UNKNOWN or is_unknown(key):
            return UNKNOWN
        if isinstance(base, dict):
            return base.get(_to_string(key), UNKNOWN)
        if isinstance(base, list):
            return base[int(key)]
        return UNKNOWN

    def _eval_Splat(self, node: hcl.Splat):
        base = self._eval(node.obj)
        if isinstance(base, Ref):
            for kind, step in node.steps:
                if kind == "attr":
                    base = base.attr(step)
            return base
        if is_unknown(base):
            return UNKNOWN
        if base is None:
            return []
        items = base if isinstance(base, list) else [base]
        out = []
        for item in items:
            for kind, step in node.steps:
                if kind == "attr":
                    item = _get_attr(item, step)
                else:
                    key = self._eval(step)
                    item = item[key] if not is_unknown(key) else UNKNOWN
            out.append(item)
        return out

    def _eval_TupleExpr(self, node: hcl.TupleExpr):
        return [self._eval(item) for item in node.items]

    def _eval_ObjectExpr(self, node: hcl.ObjectExpr):
        out = {}
        for key_node, value_node in node.items:
            key = self._eval(key_node)
            if is_unknown(key):
                continue
            out[_to_string(key)] = self._eval(value_node)
        return out

    def _eval_Conditional(self, node: hcl.Conditional):
        cond = self._eval(node.cond)
        if isinstance(cond, bool):
            return self._eval(node.true if cond else node.false)
        return UNKNOWN

    def _eval_UnaryOp(self, node: hcl.UnaryOp):
        value = self._eval(node.operand)
        if is_unknown(value):
            return UNKNOWN
        if node.op == "!":
            return not _to_bool(value)
        return -_to_number(value)

    def _eval_BinaryOp(self, node: hcl.BinaryOp):
        op = node.op
        left = self._eval(node.left)
        if op in ("&&", "||"):
            if not is_unknown(left):
                lb = _to_bool(left)
                if op == "&&" and not lb:
                    return False
                if op == "||" and lb:
                    return True
            right = self._eval(node.right)
            if is_unknown(left) or is_unknown(right):
                return UNKNOWN
            return _to_bool(right)
        right = self._eval(node.right)
        if contains_unknown(left) or contains_unknown(right):
            return UNKNOWN
        if op == "==":
            return _equal(left, right)
        if op == "!=":
            return not _equal(left, right)
        a, b = _to_number(left), _to_number(right)
        ops: dict[str, Callable] = {
            "+": lambda: a + b,
            "-": lambda: a - b,
            "*": lambda: a * b,
            "/": lambda: a / b,
            "%": lambda: a % b,
            "<": lambda: a < b,
            ">": lambda: a > b,
            "<=": lambda: a <= b,
            ">=": lambda: a >= b,
        }
        result = ops[op]()
        if isinstance(result, float) and result.is_integer() and op != "/":
            return int(result)
        return result

    def _eval_ForExpr(self, node: hcl.ForExpr):
        coll = self._eval(node.collection)
        if contains_unknown(coll) and not isinstance(coll, (list, dict)):
            return UNKNOWN
        if isinstance(coll, dict):
            pairs = list(coll.items())
        elif isinstance(coll, list):
            pairs = list(enumerate(coll))
        else:
            return UNKNOWN
        tuple_out: list = []
        obj_out: dict = {}
        for k, v in pairs:
            bindings = {node.value_var: v}
            if node.key_var:
                bindings[node.key_var] = k
            scope = self.with_scope(bindings)
            if node.cond is not None:
                c = scope._eval(node.cond)
                if not isinstance(c, bool):
                    return UNKNOWN
                if not c:
                    continue
            value = scope._eval(node.value_expr)
            if node.key_expr is None:
                tuple_out.append(value)
                continue
            key = scope._eval(node.key_expr)
            if is_unknown(key):
                return UNKNOWN
            key = _to_string(key)
            if node.grouping:
                obj_out.setdefault(key, []).append(value)
            else:
                obj_out[key] = value
        return tuple_out if node.key_expr is None else obj_out

    def _eval_Call(self, node: hcl.Call):
        name = node.name.split("::")[-1] if node.name.startswith("provider::") else node.name
        func = FUNCTIONS.get(name)
        if func is None:
            return UNKNOWN
        args = [self._eval(a) for a in node.args]
        if node.expand_final and args:
            last = args.pop()
            if not isinstance(last, list):
                return UNKNOWN
            args.extend(last)
        if name in _UNKNOWN_TOLERANT:
            return func(*args)
        if any(contains_unknown(a) for a in args):
            return UNKNOWN
        return func(*args)


def _get_attr(base, name: str):
    if isinstance(base, Ref):
        return base.attr(name)
    if isinstance(base, LazyNamespace):
        return base.get(name)
    if isinstance(base, dict):
        return base.get(name, UNKNOWN)
    return UNKNOWN


def _to_string(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if value is None:
        raise EvalError("null in string")
    if isinstance(value, (dict, list)):
        raise EvalError("collection in string")
    return str(value)


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value in ("true", "false"):
        return value == "true"
    raise EvalError(f"not a bool: {value!r}")


def _to_number(value):
    if isinstance(value, bool):
        raise EvalError("bool is not a number")
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return float(value)
    raise EvalError(f"not a number: {value!r}")


def _equal(a, b) -> bool:
    if (
        isinstance(a, (int, float))
        and isinstance(b, (int, float))
        and not isinstance(a, bool)
        and not isinstance(b, bool)
    ):
        return a == b
    return type(a) is type(b) and a == b


# ---------------------------------------------------------------------------
# Built-in functions (the subset that matters for security analysis)
# ---------------------------------------------------------------------------


def _jsonencode(value):
    if contains_unknown(value):
        return EncodedJSON(value)
    return json.dumps(value, separators=(",", ":"))


def _jsondecode(text):
    return json.loads(text)


def _merge(*maps):
    out = {}
    for m in maps:
        if m is None:
            continue
        if not isinstance(m, dict):
            raise EvalError("merge expects maps")
        out.update(m)
    return out


def _flatten(items):
    out = []
    for item in items:
        if isinstance(item, list):
            out.extend(_flatten(item))
        else:
            out.append(item)
    return out


def _lookup(m, key, *default):
    if key in m:
        return m[key]
    if default:
        return default[0]
    raise EvalError("lookup: missing key")


def _coalesce(*values):
    for v in values:
        if v is not None and v != "":
            return v
    raise EvalError("coalesce: no non-null arguments")


def _try(*values):
    for v in values:
        if not contains_unknown(v):
            return v
    return UNKNOWN


def _format(fmt, *args):
    # Only %s/%d/%v style verbs; anything fancier comes back unknown.
    out, i, n = [], 0, 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and i + 1 < len(fmt):
            verb = fmt[i + 1]
            if verb == "%":
                out.append("%")
            elif verb in "sdvq":
                arg = args[n]
                n += 1
                out.append(json.dumps(arg) if verb == "q" else _to_string(arg))
            else:
                raise EvalError("unsupported format verb")
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _cidrsubnet(prefix, newbits, netnum):
    net = ipaddress.ip_network(prefix, strict=False)
    return str(list(net.subnets(prefixlen_diff=int(newbits)))[int(netnum)])


FUNCTIONS: dict[str, Callable] = {
    "jsonencode": _jsonencode,
    "jsondecode": _jsondecode,
    "merge": _merge,
    "concat": lambda *lists: [x for lst in lists for x in lst],
    "flatten": _flatten,
    "distinct": lambda lst: list(dict.fromkeys(lst)) if all(not isinstance(x, (dict, list)) for x in lst) else lst,
    "compact": lambda lst: [x for x in lst if x not in (None, "")],
    "tolist": list,
    "toset": lambda lst: list(dict.fromkeys(lst)) if all(not isinstance(x, (dict, list)) for x in lst) else list(lst),
    "tomap": dict,
    "tostring": _to_string,
    "tonumber": _to_number,
    "tobool": _to_bool,
    "lower": lambda s: s.lower(),
    "upper": lambda s: s.upper(),
    "trimspace": lambda s: s.strip(),
    "join": lambda sep, lst: sep.join(_to_string(x) for x in lst),
    "split": lambda sep, s: s.split(sep),
    "replace": lambda s, old, new: s.replace(old, new),
    "format": _format,
    "length": len,
    "keys": lambda m: sorted(m.keys()),
    "values": lambda m: [m[k] for k in sorted(m.keys())],
    "lookup": _lookup,
    "element": lambda lst, i: lst[int(i) % len(lst)],
    "contains": lambda lst, v: any(_equal(x, v) for x in lst),
    "coalesce": _coalesce,
    "try": _try,
    "can": lambda v: not contains_unknown(v),
    "max": max,
    "min": min,
    "cidrsubnet": _cidrsubnet,
    "list": lambda *items: list(items),
    "map": lambda *kv: dict(zip(kv[::2], kv[1::2], strict=False)),
}

_UNKNOWN_TOLERANT = {"jsonencode", "try", "concat", "merge", "flatten", "tolist", "toset", "list"}
