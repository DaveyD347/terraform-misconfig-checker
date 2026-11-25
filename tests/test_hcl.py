import pytest

from tfcheck import hcl


def parse_attr(src: str):
    return hcl.parse(src).body.attributes


def test_blocks_labels_and_lines():
    f = hcl.parse('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n\n  versioning {\n    enabled = true\n  }\n}\n')
    (block,) = f.body.blocks
    assert block.type == "resource" and block.labels == ["aws_s3_bucket", "b"]
    assert block.line == 1 and block.end_line == 7
    assert block.body.attributes["bucket"].line == 2
    assert block.body.blocks[0].type == "versioning" and block.body.blocks[0].line == 4


def test_single_line_block_and_empty_block():
    f = hcl.parse('provider "azurerm" { features {} }\nlocals { a = 1 }\n')
    assert [b.type for b in f.body.blocks] == ["provider", "locals"]
    assert f.body.blocks[0].body.blocks[0].type == "features"


@pytest.mark.parametrize(
    "src",
    [
        "a = 1 # trailing comment\n",
        "// line comment\na = 1\n",
        "/* block\ncomment */ a = 1\n",
    ],
)
def test_comments(src):
    assert "a" in parse_attr(src)


def test_comments_are_recorded_by_line():
    f = hcl.parse("# first\na = 1 // second\n/* third */\n")
    assert f.comments == {1: ["# first"], 2: ["// second"], 3: ["/* third */"]}


def test_template_with_interpolation_and_escapes():
    expr = parse_attr('a = "x-${var.y}-\\"q\\"-$${literal}"\n')["a"].expr
    assert isinstance(expr, hcl.Template)
    assert expr.parts[0] == "x-"
    assert isinstance(expr.parts[1], hcl.GetAttr)
    assert expr.parts[2] == '-"q"-${literal}'


def test_nested_strings_inside_interpolation():
    expr = parse_attr('a = "${join(",", ["a}", "b"])}"\n')["a"].expr
    assert isinstance(expr.parts[0], hcl.Call)


def test_heredoc_and_indented_heredoc():
    f = hcl.parse("a = <<EOT\nhello\n  ${x}\nEOT\nb = <<-EOT\n    one\n      two\n    EOT\nc = 1\n")
    a = f.body.attributes["a"].expr
    assert a.parts[0] == "hello\n  "
    b = f.body.attributes["b"].expr
    assert b.parts == ["one\n  two\n"]
    assert f.body.attributes["c"].line == 9


def test_multiline_collections_and_calls():
    src = """
a = [
  1,
  2,
]
b = {
  x = 1
  "y" = 2,
  z: 3
}
c = merge(
  local.a,
  { k = "v" },
)
"""
    attrs = parse_attr(src)
    assert len(attrs["a"].expr.items) == 2
    assert len(attrs["b"].expr.items) == 3
    assert len(attrs["c"].expr.args) == 2


def test_operator_precedence():
    expr = hcl.parse_expression("1 + 2 * 3 == 7 && !false || x")
    assert isinstance(expr, hcl.BinaryOp) and expr.op == "||"
    assert expr.left.op == "&&"


def test_conditional_and_for_expressions():
    attrs = parse_attr(
        'a = var.x ? "y" : "z"\nb = [for s in var.l : upper(s) if s != ""]\nc = {for k, v in var.m : k => v...}\n'
    )
    assert isinstance(attrs["a"].expr, hcl.Conditional)
    assert isinstance(attrs["b"].expr, hcl.ForExpr) and attrs["b"].expr.cond is not None
    assert attrs["c"].expr.grouping and attrs["c"].expr.key_var == "k"


def test_multiline_conditional_in_parentheses():
    attrs = parse_attr('a = (\n  var.x\n  ? "y"\n  : "z"\n)\nb = 1\n')
    assert isinstance(attrs["a"].expr, hcl.Conditional)
    assert attrs["b"].line == 6


def test_traversals_and_splats():
    attrs = parse_attr("a = aws_instance.web[0].id\nb = aws_instance.web[*].id\nc = var.list.0\nd = x.*.y\n")
    assert isinstance(attrs["a"].expr, hcl.GetAttr)
    assert isinstance(attrs["b"].expr, hcl.Splat) and attrs["b"].expr.steps == [("attr", "id")]
    assert isinstance(attrs["c"].expr, hcl.Index)
    assert isinstance(attrs["d"].expr, hcl.Splat)


def test_provider_function_call():
    expr = hcl.parse_expression('provider::aws::arn_parse("arn:aws:s3:::b")')
    assert isinstance(expr, hcl.Call) and expr.name == "provider::aws::arn_parse"


def test_directive_template():
    expr = parse_attr('a = "%{ if var.x }yes%{ endif }"\n')["a"].expr
    assert any(isinstance(p, hcl.Directive) for p in expr.parts)


def test_numbers():
    attrs = parse_attr("a = 10\nb = 1.5\nc = 1e3\nd = -4\n")
    assert [attrs[k].expr.value for k in "abcd"] == [10, 1.5, 1000.0, -4]


@pytest.mark.parametrize(
    "src, message",
    [
        ('a = "unterminated\n', "newline in quoted string"),
        ("a = 1 b = 2\n", "expected newline"),
        ('resource "x" "y" {\n', "expected attribute or block name"),
        ("a = <<EOT\nnever closed\n", "unterminated heredoc"),
        ("a = 1\na = 2\n", "duplicate attribute"),
        ("a = [1, 2\n", "expected"),
        ("a = @\n", "unexpected character"),
    ],
)
def test_syntax_errors_have_line_numbers(src, message):
    with pytest.raises(hcl.HCLError) as exc:
        hcl.parse(src, "bad.tf")
    assert message in exc.value.message
    assert exc.value.line >= 1
    assert "bad.tf" in str(exc.value)


def test_bom_and_crlf():
    f = hcl.parse('﻿a = "x"\r\nb = 2\r\n')
    assert set(f.body.attributes) == {"a", "b"}


def test_real_world_syntax_coverage():
    """Type constraints, validation, lifecycle, moved/import/check blocks, templates and comments everywhere."""
    from conftest import ROOT

    path = ROOT / "tests" / "fixtures" / "syntax_coverage.tf"
    f = hcl.parse(path.read_text(), str(path))
    assert [b.type for b in f.body.blocks] == [
        "variable",
        "locals",
        "resource",
        "moved",
        "import",
        "check",
        "output",
        "resource",
    ]
