import json

import pytest

from conftest import EXAMPLES
from tfcheck import __version__
from tfcheck.cli import main
from tfcheck.rules import all_rules

INSECURE = str(EXAMPLES / "insecure")
SECURE = str(EXAMPLES / "secure")


def run(capsys, *args):
    code = main([*args, "--no-config"] if args and args[0] not in ("rules", "explain") else list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_default_command_is_scan(capsys):
    code, out, _ = run(capsys, INSECURE)
    assert code == 1
    assert "AWS-EC2-001" in out and "findings" in out


def test_secure_example_exits_zero(capsys):
    code, out, _ = run(capsys, "scan", SECURE)
    assert code == 0
    assert out.strip().startswith("0 findings")


@pytest.mark.parametrize("threshold, expected", [("critical", 1), ("none", 0)])
def test_fail_on(capsys, threshold, expected):
    code, _, _ = run(capsys, INSECURE, "--fail-on", threshold)
    assert code == expected


def test_fail_on_threshold_above_findings(capsys, tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_sns_topic" "t" {}\n')
    code, _, _ = run(capsys, str(tmp_path), "--fail-on", "medium")
    assert code == 0


def test_json_output(capsys):
    code, out, _ = run(capsys, INSECURE, "--format", "json")
    doc = json.loads(out)
    assert doc["tool"] == "tfcheck" and doc["version"] == __version__
    assert doc["summary"]["findings"] == len([f for f in doc["findings"] if not f["suppressed"]])
    assert doc["summary"]["suppressed"] == 1
    first = doc["findings"][0]
    assert {"rule_id", "severity", "resource", "file", "line", "message", "remediation"} <= set(first)
    assert first["severity"] == "critical"  # sorted most severe first


def test_sarif_output(capsys, tmp_path):
    out_file = tmp_path / "out.sarif"
    code, out, _ = run(capsys, INSECURE, "--format", "sarif", "--output", str(out_file))
    assert out == ""
    doc = json.loads(out_file.read_text())
    assert doc["version"] == "2.1.0"
    run_ = doc["runs"][0]
    rules = run_["tool"]["driver"]["rules"]
    assert len(rules) == len(all_rules())
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) > 0
    for result in run_["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        loc = result["locations"][0]["physicalLocation"]
        assert not loc["artifactLocation"]["uri"].startswith("/")
        assert loc["region"]["startLine"] >= 1
    suppressed = [r for r in run_["results"] if "suppressions" in r]
    assert len(suppressed) == 1 and suppressed[0]["ruleId"] == "AWS-LAMBDA-001"


def test_markdown_output(capsys):
    code, out, _ = run(capsys, INSECURE, "--format", "markdown")
    assert out.startswith("## Terraform misconfiguration report")
    assert "| 🟣 Critical |" in out and "How to fix" in out and "Suppressed findings" in out


def test_skip_and_only(capsys):
    _, out, _ = run(capsys, INSECURE, "--only", "AWS-S3-001,AWS-S3-003", "--format", "json")
    assert {f["rule_id"] for f in json.loads(out)["findings"]} == {"AWS-S3-001", "AWS-S3-003"}
    _, out, _ = run(capsys, INSECURE, "--skip", "AWS-S3-001", "--format", "json")
    assert "AWS-S3-001" not in {f["rule_id"] for f in json.loads(out)["findings"]}


def test_var_flag(capsys, tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "public" {\n  default = false\n}\n'
        'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = var.public\n}\n'
    )
    assert run(capsys, str(tmp_path))[0] == 0
    assert run(capsys, str(tmp_path), "--var", "public=true")[0] == 1


def test_var_file_flag(capsys, tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "public" {\n  default = false\n}\n'
        'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = var.public\n}\n'
    )
    vf = tmp_path / "prod.tfvars.json"
    vf.write_text('{"public": true}')
    assert run(capsys, str(tmp_path), "--var-file", str(vf))[0] == 1


def test_parse_error_exit_code(capsys, tmp_path):
    (tmp_path / "main.tf").write_text("resource {\n")
    code, out, _ = run(capsys, str(tmp_path))
    assert code == 2
    assert "error:" in out


def test_missing_path(capsys):
    code, _, err = run(capsys, "does/not/exist")
    assert code == 2 and "does/not/exist" in err


def test_rules_command(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0 and f"{len(all_rules())} rules" in out
    code, out, _ = run(capsys, "rules", "--provider", "gcp", "--format", "json")
    assert {r["provider"] for r in json.loads(out)} == {"gcp"}


def test_explain_command(capsys):
    code, out, _ = run(capsys, "explain", "aws-iam-001")
    assert code == 0 and "AWS-IAM-001" in out and "tfcheck:ignore=AWS-IAM-001" in out
    code, _, err = run(capsys, "explain", "NOPE")
    assert code == 2 and "unknown rule" in err


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_github_mode(capsys, tmp_path, monkeypatch):
    summary, outputs = tmp_path / "summary.md", tmp_path / "out.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    sarif = tmp_path / "r.sarif"
    code, out, _ = run(capsys, INSECURE, "--github", "--sarif-file", str(sarif), "--format", "json")
    assert code == 1
    assert "::error file=" in out and ",line=" in out and "title=AWS-" in out
    assert summary.read_text().startswith("## Terraform misconfiguration report")
    lines = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert int(lines["findings"]) == sum(int(lines[s]) for s in ("critical", "high", "medium", "low"))
    assert json.loads(sarif.read_text())["version"] == "2.1.0"


def test_rules_doc_is_up_to_date():
    import importlib.util

    from conftest import ROOT

    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "gen_rules_doc.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert (ROOT / "docs" / "rules.md").read_text(encoding="utf-8") == gen.render(), (
        "docs/rules.md is stale: run python scripts/gen_rules_doc.py"
    )
