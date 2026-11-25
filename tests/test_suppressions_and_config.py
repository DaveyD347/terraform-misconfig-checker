import pytest

from conftest import ids
from tfcheck.engine import Config, scan
from tfcheck.model import parse_suppression
from tfcheck.rules import Severity

OPEN_DB = """resource "aws_db_instance" "d" {{
{inside}
  storage_encrypted   = true
  publicly_accessible = true{trailing}
  backup_retention_period = 0
}}
"""


def _db(above: str = "", inside: str = "", trailing: str = "") -> str:
    return above + OPEN_DB.format(inside=inside, trailing=trailing)


@pytest.mark.parametrize(
    "text, ids_, reason",
    [
        ("# tfcheck:ignore", None, ""),
        ("# tfcheck:ignore=AWS-RDS-002 BI tool needs it", {"AWS-RDS-002"}, "BI tool needs it"),
        ("// tfcheck:ignore:aws-rds-002,AWS-RDS-003 -- legacy", {"AWS-RDS-002", "AWS-RDS-003"}, "legacy"),
        ("/* tfcheck:ignore=AWS-S3-001 */", {"AWS-S3-001"}, ""),
    ],
)
def test_parse_suppression(text, ids_, reason):
    sup = parse_suppression(text, 1)
    assert sup.rule_ids == (frozenset(ids_) if ids_ else None)
    assert sup.reason == reason


def test_unrelated_comment_is_not_a_suppression():
    assert parse_suppression("# public bucket for the website", 1) is None


def test_comment_above_resource_suppresses_matching_rule_only(scan_tf):
    result = scan_tf(_db(above="# tfcheck:ignore=AWS-RDS-002 reporting replica\n"))
    assert ids(result) == ["AWS-RDS-003"]
    (sup,) = result.suppressed
    assert sup.rule.id == "AWS-RDS-002" and sup.suppression_reason == "reporting replica"


def test_comment_at_top_of_block_suppresses_whole_resource(scan_tf):
    result = scan_tf(_db(inside="  # tfcheck:ignore"))
    assert ids(result) == []
    assert len(result.suppressed) == 2


def test_trailing_comment_only_covers_its_line(scan_tf):
    result = scan_tf(_db(trailing="  # tfcheck:ignore"))
    assert ids(result) == ["AWS-RDS-003"]


def test_comment_on_own_line_covers_the_next_line(scan_tf):
    src = 'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n  # tfcheck:ignore=AWS-RDS-002\n'
    src += "  publicly_accessible = true\n  backup_retention_period = 0\n}\n"
    assert ids(scan_tf(src)) == ["AWS-RDS-003"]


def test_suppression_does_not_leak_to_other_resources(scan_tf):
    src = _db(above="# tfcheck:ignore\n") + 'resource "aws_efs_file_system" "f" {}\n'
    assert ids(scan_tf(src)) == ["AWS-EFS-001"]


def test_config_file_is_applied(scan_tf, tmp_path, monkeypatch):
    (tmp_path / ".tfcheck.toml").write_text(
        'skip_rules = ["AWS-RDS-003"]\nseverity_overrides = { "AWS-RDS-002" = "critical" }\nfail_on = "high"\n'
    )
    (tmp_path / "main.tf").write_text(_db())
    monkeypatch.chdir(tmp_path)
    from tfcheck.engine import find_config

    cfg = Config.from_file(find_config(["."]))
    result = scan(["."], cfg)
    assert ids(result) == ["AWS-RDS-002"]
    assert result.active[0].severity == Severity.CRITICAL
    assert cfg.fail_on == Severity.HIGH


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "tfcheck.toml"
    path.write_text('skip = ["AWS-S3-001"]\n')
    with pytest.raises(ValueError, match="unknown setting"):
        Config.from_file(path)


def test_unknown_rule_ids_are_rejected(scan_tf):
    with pytest.raises(ValueError, match="unknown rule id"):
        scan_tf("", config=Config(skip_rules={"AWS-NOPE-001"}))


def test_min_severity_filters(scan_tf):
    result = scan_tf(_db(), config=Config(min_severity=Severity.HIGH))
    assert ids(result) == ["AWS-RDS-002"]


def test_exclude_paths(scan_tf):
    result = scan_tf(
        files={"prod/main.tf": 'resource "aws_efs_file_system" "f" {}\n', "sandbox/main.tf": _db()},
        config=Config(exclude_paths=["sandbox"]),
    )
    assert ids(result) == ["AWS-EFS-001"]


def test_parse_errors_are_reported_and_other_files_still_scanned(scan_tf):
    result = scan_tf(
        files={
            "a/broken.tf": 'resource "x" "y" {\n  a = \n}\n',
            "b/main.tf": 'resource "aws_efs_file_system" "f" {}\n',
        }
    )
    assert ids(result) == ["AWS-EFS-001"]
    (err,) = result.errors
    assert err.file.endswith("broken.tf") and err.line == 2


def test_hidden_and_vendor_directories_are_skipped(scan_tf):
    result = scan_tf(files={".terraform/modules/x/main.tf": 'resource "aws_efs_file_system" "f" {}\n'})
    assert ids(result) == []


def test_example_config_is_valid():
    from conftest import ROOT

    cfg = Config.from_file(ROOT / ".tfcheck.example.toml")
    assert cfg.fail_on == Severity.HIGH and "AWS-S3-004" in cfg.skip_rules
