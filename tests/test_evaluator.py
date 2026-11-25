import pytest

from tfcheck import hcl
from tfcheck.evaluator import UNKNOWN, EncodedJSON, Evaluator, Ref


def ev(src, variables=None, locals_src=None):
    locals_ = {}
    if locals_src:
        locals_ = {k: a.expr for k, a in hcl.parse(locals_src).body.attributes.items()}
    return Evaluator(variables or {}, locals_).eval(hcl.parse_expression(src))


@pytest.mark.parametrize(
    "src, expected",
    [
        ('"a-${1 + 1}"', "a-2"),
        ("[1, 2][1]", 2),
        ('{a = 1, "b" = 2}', {"a": 1, "b": 2}),
        ("true ? 1 : 2", 1),
        ("!true || 3 > 2", True),
        ("10 / 4", 2.5),
        ("7 % 4", 3),
        ('upper("x")', "X"),
        ('join(",", ["a", "b"])', "a,b"),
        ("merge({a = 1}, {b = 2})", {"a": 1, "b": 2}),
        ("concat([1], [2, 3])", [1, 2, 3]),
        ('length("abc")', 3),
        ('lookup({a = 1}, "b", 5)', 5),
        ('format("%s:%d", "port", 22)', "port:22"),
        ('cidrsubnet("10.0.0.0/16", 8, 2)', "10.0.2.0/24"),
        ('[for s in ["a", "b"] : upper(s)]', ["A", "B"]),
        ("{for k, v in {a = 1, b = 2} : v => k if v > 1}", {"2": "b"}),
        ('jsondecode("{\\"a\\": [1]}")', {"a": [1]}),
        ("tostring(true)", "true"),
        ("[{a = 1}, {a = 2}][*].a", [1, 2]),
    ],
)
def test_constant_folding(src, expected):
    assert ev(src) == expected


def test_variables_and_locals():
    assert ev("var.cidr", {"cidr": "0.0.0.0/0"}) == "0.0.0.0/0"
    assert ev("local.b", locals_src='a = "x"\nb = "${local.a}-y"\n') == "x-y"


def test_missing_variable_is_unknown():
    assert ev("var.nope") is UNKNOWN


def test_cyclic_locals_do_not_recurse_forever():
    assert ev("local.a", locals_src="a = local.b\nb = local.a\n") is UNKNOWN


def test_resource_references_become_refs():
    value = ev("aws_s3_bucket.logs.id")
    assert isinstance(value, Ref) and value.address == "aws_s3_bucket.logs.id"
    assert value.refers_to("aws_s3_bucket.logs") and not value.refers_to("aws_s3_bucket.log")
    assert ev("aws_instance.web[0].id").address == "aws_instance.web.id"
    assert ev("data.aws_iam_policy_document.x.json").address == "data.aws_iam_policy_document.x.json"


@pytest.mark.parametrize("src", ["each.value", "count.index", "module.vpc.id", "path.module", "unknownfunc(1)"])
def test_unknowable_values(src):
    assert ev(src) is UNKNOWN


def test_unknown_propagates_through_operators_and_templates():
    assert ev("var.x + 1") is UNKNOWN
    assert ev('"${var.x}-suffix"') is UNKNOWN
    assert ev("var.x ? 1 : 2") is UNKNOWN


def test_short_circuit_logic_with_unknowns():
    assert ev("false && var.x") is False
    assert ev("true || var.x") is True


def test_jsonencode_known_and_partial():
    assert ev('jsonencode({a = "b"})') == '{"a":"b"}'
    partial = ev("jsonencode({Resource = aws_s3_bucket.b.arn})")
    assert isinstance(partial, EncodedJSON)
    assert partial.data["Resource"] == Ref("aws_s3_bucket.b.arn")


def test_try_returns_first_known_value():
    assert ev('try(var.missing, "fallback")') == "fallback"


def test_errors_become_unknown():
    assert ev("1 / 0") is UNKNOWN
    assert ev("[1][5]") is UNKNOWN
