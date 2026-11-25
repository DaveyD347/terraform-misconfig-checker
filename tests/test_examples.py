"""The examples double as end-to-end regression tests."""

from collections import Counter

from conftest import EXAMPLES
from tfcheck.engine import scan


def _counts(path):
    result = scan([str(EXAMPLES / path)])
    assert not result.errors
    return Counter(f.rule.id for f in result.active), result


def test_insecure_aws_example():
    counts, result = _counts("insecure/aws")
    assert counts == Counter(
        {
            "AWS-EC2-001": 4,
            "AWS-S3-002": 2,
            "AWS-S3-004": 2,
            "AWS-EC2-002": 2,
            "AWS-S3-001": 1,
            "AWS-S3-003": 1,
            "AWS-EC2-003": 1,
            "AWS-EC2-004": 1,
            "AWS-RDS-001": 1,
            "AWS-RDS-002": 1,
            "AWS-RDS-003": 1,
            "AWS-IAM-001": 1,
            "AWS-IAM-002": 1,
            "AWS-IAM-003": 1,
            "AWS-IAM-004": 1,
            "AWS-IAM-005": 1,
            "AWS-KMS-001": 1,
            "AWS-CT-001": 1,
            "AWS-CT-002": 1,
            "AWS-CT-003": 1,
            "AWS-ELB-001": 1,
            "AWS-ELB-002": 1,
            "AWS-EKS-001": 1,
            "AWS-SQS-001": 1,
        }
    )
    assert [f.rule.id for f in result.suppressed] == ["AWS-LAMBDA-001"]


def test_tfvars_override_is_what_opens_the_bastion():
    _, result = _counts("insecure/aws")
    bastion = [f for f in result.active if f.resource.address == "aws_security_group_rule.bastion_ssh"]
    assert len(bastion) == 1 and "0.0.0.0/0" in bastion[0].message


def test_insecure_azure_example():
    counts, _ = _counts("insecure/azure")
    assert counts == Counter(
        {
            "AZ-NET-001": 2,
            "AZ-STORAGE-001": 1,
            "AZ-STORAGE-002": 1,
            "AZ-STORAGE-003": 1,
            "AZ-SQL-001": 1,
            "AZ-KV-001": 1,
        }
    )


def test_insecure_gcp_example():
    counts, _ = _counts("insecure/gcp")
    assert counts == Counter(
        {
            "GCP-STORAGE-001": 1,
            "GCP-STORAGE-002": 1,
            "GCP-NET-001": 1,
            "GCP-SQL-001": 1,
            "GCP-SQL-002": 1,
            "GCP-IAM-002": 1,
            "GCP-COMPUTE-001": 1,
        }
    )


def test_secure_example_is_clean():
    counts, result = _counts("secure")
    assert counts == Counter()
    assert result.resource_count >= 10
