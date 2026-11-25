import json

from conftest import EXAMPLES, ids
from tfcheck.engine import scan
from tfcheck.evaluator import UNKNOWN, Ref
from tfcheck.plan import _module_prefix, load_plan

PLAN = EXAMPLES / "plan" / "tfplan.json"


def test_example_plan_findings():
    result = scan([str(PLAN)])
    assert not result.errors
    assert ids(result) == ["AWS-EC2-001", "AWS-IAM-001", "AWS-S3-002"]
    sg = next(f for f in result.active if f.rule.id == "AWS-EC2-001")
    assert sg.resource.address == "module.app.aws_security_group.this[0]"
    assert sg.line is None and sg.file.endswith("tfplan.json")


def test_references_from_configuration_link_resources():
    module = load_plan(json.loads(PLAN.read_text()), "tfplan.json")
    pab = next(r for r in module.resources if r.type == "aws_s3_bucket_public_access_block")
    assert pab.config["bucket"] == Ref("aws_s3_bucket.reports.id")
    bucket = next(r for r in module.resources if r.type == "aws_s3_bucket")
    assert module.links_to(pab.config["bucket"], bucket)


def test_after_unknown_marks_values_unknown():
    module = load_plan(json.loads(PLAN.read_text()), "tfplan.json")
    web = next(r for r in module.resources if r.type == "aws_instance")
    assert web.config["root_block_device"] is UNKNOWN


def test_module_prefix():
    assert _module_prefix("aws_s3_bucket.b") == ""
    assert _module_prefix("module.a.aws_s3_bucket.b") == "module.a."
    assert _module_prefix('module.a["x.y"].module.b[0].aws_s3_bucket.c') == "module.a.module.b."


def test_state_documents_are_accepted(tmp_path):
    state = {
        "format_version": "1.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_efs_file_system.f",
                        "mode": "managed",
                        "type": "aws_efs_file_system",
                        "name": "f",
                        "values": {"encrypted": False},
                    }
                ]
            }
        },
    }
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state))
    assert ids(scan([str(path)])) == ["AWS-EFS-001"]


def test_non_plan_json_is_an_error(tmp_path):
    path = tmp_path / "package.json"
    path.write_text('{"name": "x"}')
    result = scan([str(path)])
    assert result.errors and "not a Terraform plan" in result.errors[0].message
