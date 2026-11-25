"""Every rule gets at least one configuration that must trigger it and one that must not."""

import pytest

from conftest import ids
from tfcheck.engine import Config
from tfcheck.rules import Severity, all_rules

# rule id -> (insecure snippet, secure snippet)
CASES = {
    # ---------------------------------------------------------------- AWS S3
    "AWS-S3-001": (
        'resource "aws_s3_bucket_acl" "a" {\n  bucket = "b"\n  acl = "public-read-write"\n}',
        'resource "aws_s3_bucket_acl" "a" {\n  bucket = "b"\n  acl = "private"\n}',
    ),
    "AWS-S3-002": (
        """
        resource "aws_s3_bucket" "b" { bucket = "b" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket = aws_s3_bucket.b.id
          block_public_acls = true
          block_public_policy = true
          ignore_public_acls = true
        }
        """,
        """
        resource "aws_s3_bucket" "b" { bucket = "b" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket = aws_s3_bucket.b.id
          block_public_acls = true
          block_public_policy = true
          ignore_public_acls = true
          restrict_public_buckets = true
        }
        """,
    ),
    "AWS-S3-003": (
        """
        resource "aws_s3_bucket_policy" "p" {
          bucket = "b"
          policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }] })
        }
        """,
        """
        resource "aws_s3_bucket_policy" "p" {
          bucket = "b"
          policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*",
            Condition = { StringEquals = { "aws:SourceVpce" = "vpce-1234" } } }] })
        }
        """,
    ),
    "AWS-S3-004": (
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}',
        """
        resource "aws_s3_bucket" "b" { bucket = "b" }
        resource "aws_s3_bucket_versioning" "b" {
          bucket = aws_s3_bucket.b.id
          versioning_configuration { status = "Enabled" }
        }
        """,
    ),
    # --------------------------------------------------------------- AWS EC2
    "AWS-EC2-001": (
        """
        resource "aws_security_group" "s" {
          ingress {
            from_port = 3389
            to_port = 3389
            protocol = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """,
        """
        resource "aws_security_group" "s" {
          ingress {
            from_port = 443
            to_port = 443
            protocol = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
          ingress {
            from_port = 22
            to_port = 22
            protocol = "tcp"
            cidr_blocks = ["10.0.0.0/8"]
          }
        }
        """,
    ),
    "AWS-EC2-002": (
        'resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n  encrypted = false\n}',
        'resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n  encrypted = true\n}',
    ),
    "AWS-EC2-003": (
        'resource "aws_launch_template" "t" {\n  name = "t"\n}',
        'resource "aws_launch_template" "t" {\n  metadata_options {\n    http_tokens = "required"\n  }\n}',
    ),
    "AWS-EC2-004": (
        """
        resource "aws_launch_template" "t" {
          metadata_options { http_tokens = "required" }
          network_interfaces { associate_public_ip_address = true }
        }
        """,
        """
        resource "aws_launch_template" "t" {
          metadata_options { http_tokens = "required" }
          network_interfaces { associate_public_ip_address = false }
        }
        """,
    ),
    "AWS-EC2-005": (
        """
        resource "aws_default_security_group" "d" {
          vpc_id = "vpc-1"
          ingress {
            protocol = -1
            self = true
            from_port = 0
            to_port = 0
          }
        }
        """,
        'resource "aws_default_security_group" "d" {\n  vpc_id = "vpc-1"\n}',
    ),
    # --------------------------------------------------------------- AWS IAM
    "AWS-IAM-001": (
        """
        data "aws_iam_policy_document" "d" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        """,
        """
        data "aws_iam_policy_document" "d" {
          statement {
            effect = "Deny"
            actions = ["*"]
            resources = ["*"]
          }
        }
        """,
    ),
    "AWS-IAM-002": (
        """
        resource "aws_iam_role_policy" "p" {
          role = "r"
          policy = jsonencode({ Statement = { Effect = "Allow", Action = "iam:*", Resource = "*" } })
        }
        """,
        """
        resource "aws_iam_role_policy" "p" {
          role = "r"
          policy = jsonencode({ Statement = { Effect = "Allow", Action = "iam:GetRole", Resource = "*" } })
        }
        """,
    ),
    "AWS-IAM-003": (
        'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n}',
        'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]\n}',
    ),
    "AWS-IAM-004": (
        """
        resource "aws_iam_role" "r" {
          assume_role_policy = <<-EOF
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
          EOF
        }
        """,
        """
        resource "aws_iam_role" "r" {
          assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
            Principal = { Service = "ec2.amazonaws.com" } }] })
        }
        """,
    ),
    "AWS-IAM-005": (
        'resource "aws_iam_user_policy_attachment" "a" {\n  user = "bob"\n  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n}',
        'resource "aws_iam_group_policy_attachment" "a" {\n  group = "devs"\n  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n}',
    ),
    # ----------------------------------------------------- AWS data services
    "AWS-RDS-001": (
        'resource "aws_rds_cluster" "c" {\n  engine = "aurora-postgresql"\n}',
        'resource "aws_rds_cluster" "c" {\n  engine = "aurora-postgresql"\n  storage_encrypted = true\n}',
    ),
    "AWS-RDS-002": (
        'resource "aws_rds_cluster_instance" "i" {\n  publicly_accessible = true\n}',
        'resource "aws_rds_cluster_instance" "i" {\n  publicly_accessible = false\n}',
    ),
    "AWS-RDS-003": (
        'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n  backup_retention_period = 0\n}',
        'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n  backup_retention_period = 7\n}',
    ),
    "AWS-REDSHIFT-001": (
        'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = true\n}',
        'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = false\n}',
    ),
    "AWS-EFS-001": (
        'resource "aws_efs_file_system" "f" {}',
        'resource "aws_efs_file_system" "f" {\n  encrypted = true\n}',
    ),
    "AWS-OS-001": (
        'resource "aws_opensearch_domain" "d" {\n  encrypt_at_rest {\n    enabled = false\n  }\n}',
        'resource "aws_opensearch_domain" "d" {\n  encrypt_at_rest {\n    enabled = true\n  }\n}',
    ),
    "AWS-CACHE-001": (
        'resource "aws_elasticache_replication_group" "r" {\n  description = "x"\n}',
        'resource "aws_elasticache_replication_group" "r" {\n  transit_encryption_enabled = true\n}',
    ),
    "AWS-SNS-001": (
        'resource "aws_sns_topic" "t" {\n  name = "t"\n}',
        'resource "aws_sns_topic" "t" {\n  kms_master_key_id = "alias/aws/sns"\n}',
    ),
    "AWS-SQS-001": (
        'resource "aws_sqs_queue" "q" {\n  sqs_managed_sse_enabled = false\n}',
        'resource "aws_sqs_queue" "q" {\n  name = "q"\n}',
    ),
    "AWS-ECR-001": (
        'resource "aws_ecr_repository" "r" {\n  name = "r"\n}',
        'resource "aws_ecr_repository" "r" {\n  image_scanning_configuration {\n    scan_on_push = true\n  }\n}',
    ),
    # --------------------------------------------------- AWS logging & keys
    "AWS-CT-001": (
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = false\n  enable_log_file_validation = true\n  kms_key_id = "k"\n}',
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n  enable_log_file_validation = true\n  kms_key_id = "k"\n}',
    ),
    "AWS-CT-002": (
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n  kms_key_id = "k"\n}',
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n  enable_log_file_validation = true\n  kms_key_id = "k"\n}',
    ),
    "AWS-CT-003": (
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n  enable_log_file_validation = true\n}',
        'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n  enable_log_file_validation = true\n  kms_key_id = "k"\n}',
    ),
    "AWS-KMS-001": (
        'resource "aws_kms_key" "k" {\n  enable_key_rotation = false\n}',
        'resource "aws_kms_key" "k" {\n  customer_master_key_spec = "RSA_2048"\n  key_usage = "SIGN_VERIFY"\n}',
    ),
    # ------------------------------------------------------- AWS compute/edge
    "AWS-EKS-001": (
        'resource "aws_eks_cluster" "c" {\n  vpc_config {\n    public_access_cidrs = ["0.0.0.0/0"]\n  }\n}',
        'resource "aws_eks_cluster" "c" {\n  vpc_config {\n    public_access_cidrs = ["198.51.100.0/24"]\n  }\n}',
    ),
    "AWS-ELB-001": (
        'resource "aws_alb_listener" "l" {\n  protocol = "HTTP"\n  default_action {\n    type = "forward"\n  }\n}',
        'resource "aws_alb_listener" "l" {\n  protocol = "HTTP"\n  default_action {\n    type = "redirect"\n  }\n}',
    ),
    "AWS-ELB-002": (
        'resource "aws_lb_listener" "l" {\n  protocol = "HTTPS"\n  default_action {\n    type = "forward"\n  }\n}',
        'resource "aws_lb_listener" "l" {\n  protocol = "TLS"\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}',
    ),
    "AWS-LAMBDA-001": (
        'resource "aws_lambda_function_url" "u" {\n  function_name = "f"\n  authorization_type = "NONE"\n}',
        'resource "aws_lambda_function_url" "u" {\n  function_name = "f"\n  authorization_type = "AWS_IAM"\n}',
    ),
    # ----------------------------------------------------------------- Azure
    "AZ-STORAGE-001": (
        'resource "azurerm_storage_account" "s" {\n  allow_nested_items_to_be_public = true\n}',
        'resource "azurerm_storage_account" "s" {\n  allow_nested_items_to_be_public = false\n}',
    ),
    "AZ-STORAGE-002": (
        'resource "azurerm_storage_account" "s" {\n  enable_https_traffic_only = false\n}',
        'resource "azurerm_storage_account" "s" {\n  enable_https_traffic_only = true\n}',
    ),
    "AZ-STORAGE-003": (
        'resource "azurerm_storage_account" "s" {\n  min_tls_version = "TLS1_1"\n}',
        'resource "azurerm_storage_account" "s" {\n  min_tls_version = "TLS1_2"\n}',
    ),
    "AZ-NET-001": (
        """
        resource "azurerm_network_security_rule" "r" {
          direction = "Inbound"
          access = "Allow"
          protocol = "Tcp"
          source_address_prefix = "Internet"
          destination_port_ranges = ["443", "3300-3310"]
        }
        """,
        """
        resource "azurerm_network_security_rule" "r" {
          direction = "Inbound"
          access = "Deny"
          protocol = "Tcp"
          source_address_prefix = "Internet"
          destination_port_range = "22"
        }
        """,
    ),
    "AZ-SQL-001": (
        'resource "azurerm_postgresql_flexible_server_firewall_rule" "f" {\n  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}',
        'resource "azurerm_postgresql_flexible_server_firewall_rule" "f" {\n  start_ip_address = "203.0.113.4"\n  end_ip_address = "203.0.113.4"\n}',
    ),
    "AZ-KV-001": (
        'resource "azurerm_key_vault" "k" {\n  purge_protection_enabled = false\n}',
        'resource "azurerm_key_vault" "k" {\n  purge_protection_enabled = true\n}',
    ),
    # ------------------------------------------------------------------- GCP
    "GCP-STORAGE-001": (
        'resource "google_storage_bucket_iam_binding" "b" {\n  role = "roles/storage.objectViewer"\n  members = ["allAuthenticatedUsers"]\n}',
        'resource "google_storage_bucket_iam_binding" "b" {\n  role = "roles/storage.objectViewer"\n  members = ["group:team@example.com"]\n}',
    ),
    "GCP-STORAGE-002": (
        'resource "google_storage_bucket" "b" {\n  name = "b"\n  uniform_bucket_level_access = false\n}',
        'resource "google_storage_bucket" "b" {\n  name = "b"\n  uniform_bucket_level_access = true\n}',
    ),
    "GCP-NET-001": (
        'resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n  }\n}',
        'resource "google_compute_firewall" "f" {\n  source_ranges = ["35.235.240.0/20"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}',
    ),
    "GCP-SQL-001": (
        """
        resource "google_sql_database_instance" "d" {
          settings {
            ip_configuration {
              ssl_mode = "ENCRYPTED_ONLY"
              authorized_networks { value = "0.0.0.0/0" }
            }
          }
        }
        """,
        """
        resource "google_sql_database_instance" "d" {
          settings {
            ip_configuration {
              ssl_mode = "ENCRYPTED_ONLY"
              authorized_networks { value = "203.0.113.0/24" }
            }
          }
        }
        """,
    ),
    "GCP-SQL-002": (
        'resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n      ipv4_enabled = true\n    }\n  }\n}',
        'resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n      ipv4_enabled = false\n    }\n  }\n}',
    ),
    "GCP-IAM-001": (
        'resource "google_project_iam_binding" "b" {\n  role = "roles/viewer"\n  members = ["allUsers"]\n}',
        'resource "google_project_iam_binding" "b" {\n  role = "roles/viewer"\n  members = ["user:a@example.com"]\n}',
    ),
    "GCP-IAM-002": (
        'resource "google_organization_iam_member" "m" {\n  role = "roles/owner"\n  member = "user:a@example.com"\n}',
        'resource "google_organization_iam_member" "m" {\n  role = "roles/viewer"\n  member = "user:a@example.com"\n}',
    ),
    "GCP-COMPUTE-001": (
        """
        resource "google_compute_instance_template" "t" {
          service_account {
            email = "123-compute@developer.gserviceaccount.com"
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
          }
        }
        """,
        """
        resource "google_compute_instance_template" "t" {
          service_account {
            email = "worker@proj.iam.gserviceaccount.com"
            scopes = ["cloud-platform"]
          }
        }
        """,
    ),
}


def test_every_rule_has_a_test_case():
    assert set(CASES) == {r.id for r in all_rules()}


def test_rule_metadata_is_complete():
    for r in all_rules():
        assert r.title and r.description and r.remediation, r.id
        assert r.resource_types, r.id
        assert r.provider in ("aws", "azure", "gcp")


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_flags_insecure_config(scan_tf, rule_id):
    bad, _ = CASES[rule_id]
    result = scan_tf(bad, config=Config(only_rules={rule_id}))
    assert ids(result) == [rule_id] * len(result.active) and result.active, f"{rule_id} did not fire"
    assert not result.errors


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_passes_secure_config(scan_tf, rule_id):
    _, good = CASES[rule_id]
    result = scan_tf(good, config=Config(only_rules={rule_id}))
    assert ids(result) == []
    assert not result.errors


# ------------------------------------------------------------- behaviour details


def test_all_ports_open_is_critical(scan_tf):
    result = scan_tf(
        'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 0\n  to_port = 65535\n'
        '  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}'
    )
    (f,) = [f for f in result.active if f.rule.id == "AWS-EC2-001"]
    assert f.severity == Severity.CRITICAL
    assert "all ports" in f.message


def test_icmp_and_egress_are_ignored(scan_tf):
    result = scan_tf(
        'resource "aws_security_group" "s" {\n'
        '  ingress {\n    from_port = -1\n    to_port = -1\n    protocol = "icmp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '  egress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'
    )
    assert ids(result) == []


def test_variable_defaults_and_tfvars_are_resolved(scan_tf):
    result = scan_tf(
        files={
            "variables.tf": 'variable "cidr" {\n  default = "10.0.0.0/8"\n}\n',
            "main.tf": 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n'
            '  protocol = "tcp"\n  cidr_blocks = [var.cidr]\n}\n',
            "terraform.tfvars": 'cidr = "0.0.0.0/0"\n',
        }
    )
    assert ids(result) == ["AWS-EC2-001"]


def test_cli_var_overrides_tfvars(scan_tf):
    result = scan_tf(
        files={
            "main.tf": 'variable "public" {\n  default = true\n}\n'
            'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n  publicly_accessible = var.public\n}\n',
        },
        variables={"public": False},
    )
    assert ids(result) == []


def test_unknown_values_do_not_create_false_positives(scan_tf):
    result = scan_tf(
        """
        variable "encrypted" {}
        resource "aws_ebs_volume" "v" {
          availability_zone = "a"
          encrypted = var.encrypted
        }
        resource "aws_security_group_rule" "r" {
          type = "ingress"
          from_port = 22
          to_port = 22
          protocol = "tcp"
          cidr_blocks = [var.unset]
        }
        """
    )
    assert ids(result) == []


def test_dynamic_blocks_are_expanded(scan_tf):
    result = scan_tf(
        """
        locals {
          rules = { ssh = 22, https = 443 }
        }
        resource "aws_security_group" "s" {
          dynamic "ingress" {
            for_each = local.rules
            content {
              from_port   = ingress.value
              to_port     = ingress.value
              protocol    = "tcp"
              cidr_blocks = ["0.0.0.0/0"]
            }
          }
        }
        """
    )
    (f,) = result.active
    assert f.rule.id == "AWS-EC2-001" and "22 (SSH)" in f.message


def test_iam_document_is_reported_once_at_the_statement(scan_tf):
    result = scan_tf(
        """
        data "aws_iam_policy_document" "admin" {
          statement {
            actions   = ["*"]
            resources = ["*"]
          }
        }

        resource "aws_iam_policy" "admin" {
          policy = data.aws_iam_policy_document.admin.json
        }
        """
    )
    (f,) = result.active
    assert f.rule.id == "AWS-IAM-001"
    assert f.resource.address == "data.aws_iam_policy_document.admin"
    assert f.line == 3


def test_trust_policy_through_policy_document(scan_tf):
    result = scan_tf(
        """
        data "aws_iam_policy_document" "trust" {
          statement {
            actions = ["sts:AssumeRole"]
            principals {
              type        = "AWS"
              identifiers = ["*"]
            }
          }
        }
        resource "aws_iam_role" "r" {
          assume_role_policy = data.aws_iam_policy_document.trust.json
        }
        """
    )
    assert ids(result) == ["AWS-IAM-004"]


def test_trust_policy_with_condition_is_allowed(scan_tf):
    result = scan_tf(
        """
        data "aws_iam_policy_document" "trust" {
          statement {
            actions = ["sts:AssumeRole"]
            principals {
              type        = "AWS"
              identifiers = ["*"]
            }
            condition {
              test     = "StringEquals"
              variable = "aws:PrincipalOrgID"
              values   = ["o-abc123"]
            }
          }
        }
        resource "aws_iam_role" "r" {
          assume_role_policy = data.aws_iam_policy_document.trust.json
        }
        """
    )
    assert ids(result) == []


def test_account_level_public_access_block_covers_buckets(scan_tf):
    result = scan_tf(
        """
        resource "aws_s3_account_public_access_block" "a" {
          block_public_acls       = true
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        resource "aws_s3_bucket" "b" {
          bucket = "b"
          versioning { enabled = true }
        }
        """
    )
    assert ids(result) == []


def test_ebs_default_encryption_covers_instances(scan_tf):
    result = scan_tf(
        """
        resource "aws_ebs_encryption_by_default" "on" { enabled = true }
        resource "aws_instance" "i" {
          metadata_options { http_tokens = "required" }
        }
        """
    )
    assert ids(result) == []


def test_finding_points_at_the_attribute_line(scan_tf):
    result = scan_tf(
        'resource "aws_db_instance" "d" {\n  engine = "postgres"\n  storage_encrypted = true\n  publicly_accessible = true\n}\n'
    )
    (f,) = result.active
    assert f.line == 4
