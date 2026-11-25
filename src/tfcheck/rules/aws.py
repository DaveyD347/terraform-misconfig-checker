"""AWS rules."""

from __future__ import annotations

from ..evaluator import UNKNOWN
from ..model import Module, Resource, as_list
from . import Issue, Severity, rule
from ._common import (
    all_statements,
    decode_policy,
    exposure_for_range,
    is_false,
    is_public_cidr,
    is_true,
    iter_statements,
    known,
    policy_from_document,
    policy_statements,
)

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

_PUBLIC_ACLS = {"public-read": H, "public-read-write": C, "authenticated-read": H}


@rule(
    "AWS-S3-001",
    "S3 bucket ACL grants public access",
    H,
    ["aws_s3_bucket", "aws_s3_bucket_acl"],
    """A canned ACL of public-read, public-read-write or authenticated-read lets
    anyone on the internet (or any AWS account) list or modify objects. Public
    ACLs are the classic cause of S3 data leaks.""",
    """Use a private ACL (or disable ACLs entirely with object ownership
"BucketOwnerEnforced") and serve public content through CloudFront with
origin access control instead.

    resource "aws_s3_bucket_ownership_controls" "this" {
      bucket = aws_s3_bucket.this.id
      rule { object_ownership = "BucketOwnerEnforced" }
    }""",
    tags=["data-exposure"],
)
def s3_public_acl(r: Resource, m: Module):
    acl = r.config.get("acl")
    if isinstance(acl, str) and acl in _PUBLIC_ACLS:
        yield Issue(f'Bucket ACL is "{acl}"', "acl", _PUBLIC_ACLS[acl])
    for i, policy in enumerate(r.blocks("access_control_policy")):
        for j, grant in enumerate(_grants(policy)):
            uri = (grant.get("grantee") or [{}])[0].get("uri", "") if isinstance(grant.get("grantee"), list) else ""
            if isinstance(uri, str) and uri.endswith(("/global/AllUsers", "/global/AuthenticatedUsers")):
                yield Issue(
                    f"ACL grant gives {grant.get('permission', 'access')} to {uri.rsplit('/', 1)[-1]}",
                    f"access_control_policy[{i}].grant[{j}]",
                )


def _grants(policy: dict) -> list[dict]:
    grants = policy.get("grant")
    return [g for g in grants if isinstance(g, dict)] if isinstance(grants, list) else []


_PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


@rule(
    "AWS-S3-002",
    "S3 bucket is not covered by a full public access block",
    M,
    ["aws_s3_bucket"],
    """S3 Block Public Access is the guard rail that stops a future ACL or bucket
    policy change from exposing data. Every bucket should have all four
    settings enabled, either on the bucket or account-wide.""",
    """resource "aws_s3_bucket_public_access_block" "this" {
      bucket                  = aws_s3_bucket.this.id
      block_public_acls       = true
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true
    }""",
    tags=["data-exposure"],
)
def s3_public_access_block(r: Resource, m: Module):
    for acct in m.of_type("aws_s3_account_public_access_block"):
        if all(is_true(acct.config.get(f)) for f in _PAB_FLAGS):
            return
    blocks = m.linked("aws_s3_bucket_public_access_block", r, "bucket", "bucket", "id")
    if not blocks:
        if m.source_kind == "plan" and _bucket_name_unknown(r):
            # A computed bucket name can't be matched by value; only flag if no
            # access block in the plan could possibly belong to this bucket.
            if m.of_type("aws_s3_bucket_public_access_block"):
                return
        yield Issue("No aws_s3_bucket_public_access_block is attached to this bucket")
        return
    for pab in blocks:
        disabled = [f for f in _PAB_FLAGS if not is_true(pab.config.get(f)) and pab.config.get(f) is not UNKNOWN]
        if disabled:
            yield Issue(
                f"Public access block {pab.address} leaves {', '.join(disabled)} disabled",
                None,
            )


def _bucket_name_unknown(r: Resource) -> bool:
    return not isinstance(r.config.get("bucket"), str)


@rule(
    "AWS-S3-003",
    "S3 bucket policy allows access from any principal",
    H,
    ["aws_s3_bucket_policy", "aws_s3_bucket"],
    """A bucket policy statement with Effect Allow and Principal "*" and no
    Condition grants that access to everyone on the internet.""",
    """Name the specific AWS principals that need access, or add a Condition
(for example aws:SourceVpce, aws:PrincipalOrgID or aws:SourceArn) that
narrows who can use the statement.""",
    tags=["data-exposure"],
)
def s3_public_policy(r: Resource, m: Module):
    for st in all_statements(r, "policy", m):
        if st.effect == "Allow" and "*" in st.principals and not st.has_condition:
            actions = ", ".join(st.actions) or "all actions"
            yield Issue(f'Statement allows {actions} to Principal "*" with no condition', "policy")


@rule(
    "AWS-S3-004",
    "S3 bucket versioning is not enabled",
    L,
    ["aws_s3_bucket"],
    """Without versioning, an overwritten or deleted object is gone for good,
    which turns ransomware or a bad deploy script into permanent data loss.""",
    """resource "aws_s3_bucket_versioning" "this" {
      bucket = aws_s3_bucket.this.id
      versioning_configuration { status = "Enabled" }
    }""",
    tags=["resilience"],
)
def s3_versioning(r: Resource, m: Module):
    inline = r.block("versioning")
    if inline is not None and is_true(inline.get("enabled")):
        return
    if inline is not None and inline.get("enabled") is UNKNOWN:
        return
    for v in m.linked("aws_s3_bucket_versioning", r, "bucket", "bucket", "id"):
        cfg = v.block("versioning_configuration") or {}
        status = cfg.get("status")
        if status == "Enabled" or status is UNKNOWN:
            return
        yield Issue(f'{v.address} sets versioning status to "{status}"')
        return
    if m.source_kind == "plan" and _bucket_name_unknown(r) and m.of_type("aws_s3_bucket_versioning"):
        return
    yield Issue("Versioning is not enabled for this bucket")


# ---------------------------------------------------------------------------
# EC2 / VPC
# ---------------------------------------------------------------------------


def _aws_ingress(r: Resource):
    """Yield (path, from_port, to_port, protocol, cidrs) for each ingress definition."""
    if r.type == "aws_security_group":
        for i, ing in enumerate(r.blocks("ingress")):
            cidrs = as_list(ing.get("cidr_blocks")) + as_list(ing.get("ipv6_cidr_blocks"))
            yield f"ingress[{i}]", ing.get("from_port"), ing.get("to_port"), ing.get("protocol"), cidrs
    elif r.type == "aws_security_group_rule":
        if r.config.get("type") == "ingress":
            cidrs = as_list(r.config.get("cidr_blocks")) + as_list(r.config.get("ipv6_cidr_blocks"))
            yield "cidr_blocks", r.config.get("from_port"), r.config.get("to_port"), r.config.get("protocol"), cidrs
    elif r.type == "aws_vpc_security_group_ingress_rule":
        cidrs = as_list(r.config.get("cidr_ipv4")) + as_list(r.config.get("cidr_ipv6"))
        path = "cidr_ipv4" if r.config.get("cidr_ipv4") is not None else "cidr_ipv6"
        yield path, r.config.get("from_port"), r.config.get("to_port"), r.config.get("ip_protocol"), cidrs


@rule(
    "AWS-EC2-001",
    "Security group allows ingress from the internet to sensitive ports",
    H,
    ["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"],
    """Remote administration (SSH, RDP, WinRM, VNC) and database or cache ports
    open to 0.0.0.0/0 or ::/0 are scanned constantly and brute-forced within
    minutes. Rules that open every port are reported as critical.""",
    """Restrict the source to known CIDR ranges or another security group, and
reach instances through SSM Session Manager or a bastion instead of
exposing admin ports.

    ingress {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["10.20.0.0/16"]
    }""",
    tags=["network"],
)
def sg_open_ingress(r: Resource, m: Module):
    for path, low, high, proto, cidrs in _aws_ingress(r):
        public = [c for c in cidrs if is_public_cidr(c)]
        if not public:
            continue
        exp = exposure_for_range(low, high, proto)
        if exp is None:
            continue
        sev = C if exp.all_ports else H
        yield Issue(f"Ingress from {', '.join(public)} to {exp.describe()}", path, sev)


def _ebs_unencrypted(block: dict) -> bool:
    return (
        not is_true(block.get("encrypted")) and block.get("encrypted") is not UNKNOWN and not block.get("snapshot_id")
    )


@rule(
    "AWS-EC2-002",
    "EBS storage is not encrypted",
    M,
    ["aws_ebs_volume", "aws_instance", "aws_launch_template"],
    """Unencrypted EBS volumes and snapshots expose data to anyone who gains
    access to a snapshot copy or the underlying storage. Encryption is free
    and has no meaningful performance cost.""",
    """Set encrypted = true on volumes and block device mappings, or turn on
account-wide default encryption:

    resource "aws_ebs_encryption_by_default" "this" {
      enabled = true
    }""",
    tags=["encryption"],
)
def ebs_unencrypted(r: Resource, m: Module):
    for d in m.of_type("aws_ebs_encryption_by_default"):
        if d.config.get("enabled") is not False:
            return
    if r.type == "aws_ebs_volume":
        if _ebs_unencrypted(r.config):
            yield Issue("Volume is not encrypted", "encrypted")
    elif r.type == "aws_instance":
        if r.config.get("root_block_device") is UNKNOWN:
            return
        root = r.blocks("root_block_device")
        for i, dev in enumerate(root or [{}]):
            if _ebs_unencrypted(dev):
                yield Issue("Root block device is not encrypted", f"root_block_device[{i}]" if root else None)
        for i, dev in enumerate(r.blocks("ebs_block_device")):
            if _ebs_unencrypted(dev):
                yield Issue(f"EBS block device {dev.get('device_name', i)} is not encrypted", f"ebs_block_device[{i}]")
    else:
        for i, mapping in enumerate(r.blocks("block_device_mappings")):
            for ebs in mapping.get("ebs") or []:
                if isinstance(ebs, dict) and not is_true(ebs.get("encrypted")) and ebs.get("encrypted") is not UNKNOWN:
                    yield Issue("Launch template block device is not encrypted", f"block_device_mappings[{i}]")


@rule(
    "AWS-EC2-003",
    "Instance metadata service allows IMDSv1",
    M,
    ["aws_instance", "aws_launch_template", "aws_launch_configuration"],
    """IMDSv1 answers unauthenticated GET requests, so any SSRF bug in an
    application on the instance can be used to steal its IAM role
    credentials. IMDSv2 requires a session token and blocks this.""",
    """metadata_options {
      http_endpoint = "enabled"
      http_tokens   = "required"
    }""",
    tags=["credentials"],
)
def imdsv2(r: Resource, m: Module):
    opts = r.block("metadata_options")
    if opts is None:
        yield Issue("metadata_options is not set, so IMDSv1 stays enabled")
        return
    if opts.get("http_endpoint") == "disabled":
        return
    tokens = opts.get("http_tokens")
    if tokens is UNKNOWN or tokens == "required":
        return
    yield Issue(f'http_tokens is "{tokens or "optional"}"', "metadata_options")


@rule(
    "AWS-EC2-004",
    "Instance gets a public IP address",
    L,
    ["aws_instance", "aws_launch_template"],
    """Instances with public IPs are directly reachable from the internet, so a
    single security group mistake exposes them. Put workloads in private
    subnets behind a load balancer or NAT.""",
    """Remove associate_public_ip_address (or set it to false) and place the
instance in a private subnet.""",
    tags=["network"],
)
def public_ip(r: Resource, m: Module):
    if is_true(r.config.get("associate_public_ip_address")):
        yield Issue("associate_public_ip_address is true", "associate_public_ip_address")
    for i, ni in enumerate(r.blocks("network_interfaces")):
        if is_true(ni.get("associate_public_ip_address")):
            yield Issue("Network interface requests a public IP", f"network_interfaces[{i}]")


@rule(
    "AWS-EC2-005",
    "Default security group allows traffic",
    L,
    ["aws_default_security_group"],
    """Resources launched without an explicit security group land in the VPC
    default group. It should allow nothing, so that mistake fails closed.""",
    """Manage the default group with no ingress or egress blocks:

    resource "aws_default_security_group" "default" {
      vpc_id = aws_vpc.main.id
    }""",
    tags=["network"],
)
def default_sg(r: Resource, m: Module):
    rules = len(r.blocks("ingress")) + len(r.blocks("egress"))
    if rules:
        yield Issue(f"Default security group defines {rules} rule(s)")


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

_POLICY_TYPES = ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"]


def _policy_sources(r: Resource, m: Module):
    if r.mode == "data":
        yield from iter_statements(policy_from_document(r), "statement")
    else:
        yield from policy_statements(r, "policy", m)
        for i, inline in enumerate(r.blocks("inline_policy")):
            doc, via = decode_policy(inline.get("policy"), m)
            if doc and via is None:
                yield from iter_statements(doc, f"inline_policy[{i}]")


@rule(
    "AWS-IAM-001",
    "IAM policy grants full administrator access",
    C,
    _POLICY_TYPES + ["aws_iam_role", "data.aws_iam_policy_document"],
    """A statement allowing Action "*" on Resource "*" is full admin. Anyone or
    anything that can use this policy can disable logging, create users and
    take over the account.""",
    """Grant only the actions and resources the workload needs. IAM Access
Analyzer can generate a least-privilege policy from CloudTrail activity.""",
    tags=["iam", "least-privilege"],
)
def iam_admin(r: Resource, m: Module):
    for st in _policy_sources(r, m):
        if st.effect != "Allow":
            continue
        if any(a in ("*", "*:*") for a in st.actions) and "*" in st.resources:
            yield Issue('Statement allows Action "*" on Resource "*"', st.path)


@rule(
    "AWS-IAM-002",
    "IAM policy uses service-wide wildcard actions",
    M,
    _POLICY_TYPES + ["aws_iam_role", "data.aws_iam_policy_document"],
    """Actions such as "s3:*" or "iam:*", or an Allow with NotAction, grant
    every current and future permission of a service, including destructive
    and privilege-escalation actions.""",
    """List the specific actions needed, for example
["s3:GetObject", "s3:PutObject"] instead of "s3:*".""",
    tags=["iam", "least-privilege"],
)
def iam_wildcards(r: Resource, m: Module):
    for st in _policy_sources(r, m):
        if st.effect != "Allow":
            continue
        if any(a in ("*", "*:*") for a in st.actions) and "*" in st.resources:
            continue  # reported by AWS-IAM-001
        wild = sorted({a for a in st.actions if a == "*" or a.endswith(":*")})
        if wild:
            yield Issue(f"Statement allows {', '.join(wild)}", st.path)
        elif st.not_actions:
            yield Issue("Statement uses Allow with NotAction, which grants everything not listed", st.path)


_ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"


@rule(
    "AWS-IAM-003",
    "AdministratorAccess managed policy is attached",
    H,
    [
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_policy_attachment",
        "aws_iam_role",
    ],
    """The AWS managed AdministratorAccess policy grants every action on every
    resource. Attaching it to roles used by workloads or CI turns any
    compromise of that workload into a full account takeover.""",
    """Attach a scoped customer managed policy instead, and reserve
administrator access for break-glass roles protected by MFA.""",
    tags=["iam", "least-privilege"],
)
def admin_attachment(r: Resource, m: Module):
    arn = r.config.get("policy_arn")
    if isinstance(arn, str) and arn.endswith(_ADMIN_POLICY_SUFFIX):
        yield Issue("Attaches arn:aws:iam::aws:policy/AdministratorAccess", "policy_arn")
    for arn in as_list(r.config.get("managed_policy_arns")):
        if isinstance(arn, str) and arn.endswith(_ADMIN_POLICY_SUFFIX):
            yield Issue("managed_policy_arns includes AdministratorAccess", "managed_policy_arns")


@rule(
    "AWS-IAM-004",
    "IAM role can be assumed by any principal",
    C,
    ["aws_iam_role"],
    """A trust policy that allows Principal "*" (or AWS "*") to call
    sts:AssumeRole without a condition lets any AWS account in the world
    assume the role.""",
    """Trust specific accounts, roles or services, and require
sts:ExternalId or aws:PrincipalOrgID conditions for cross-account access.""",
    tags=["iam"],
)
def open_trust(r: Resource, m: Module):
    for st in all_statements(r, "assume_role_policy", m):
        if st.effect == "Allow" and "*" in st.principals and not st.has_condition:
            yield Issue('Trust policy allows Principal "*" without a condition', "assume_role_policy")


@rule(
    "AWS-IAM-005",
    "IAM policy is attached directly to a user",
    L,
    ["aws_iam_user_policy", "aws_iam_user_policy_attachment"],
    """Permissions granted to individual users are hard to audit and tend to
    outlive the person's role. Grant permissions to groups or roles.""",
    """Attach the policy to an aws_iam_group and add the user to the group,
or move humans to IAM Identity Center.""",
    tags=["iam"],
)
def user_policy(r: Resource, m: Module):
    yield Issue("Policy is attached to an IAM user instead of a group or role")


# ---------------------------------------------------------------------------
# Databases and storage services
# ---------------------------------------------------------------------------


@rule(
    "AWS-RDS-001",
    "RDS storage is not encrypted",
    H,
    ["aws_db_instance", "aws_rds_cluster"],
    """Unencrypted database storage, snapshots and read replicas expose data at
    rest. Encryption can only be enabled when the database is created, so it
    is expensive to fix later.""",
    """storage_encrypted = true
kms_key_id        = aws_kms_key.rds.arn  # optional customer managed key""",
    tags=["encryption"],
)
def rds_encryption(r: Resource, m: Module):
    if r.type == "aws_rds_cluster" and r.config.get("engine_mode") == "serverless":
        return  # Aurora Serverless v1 is always encrypted
    if r.type == "aws_db_instance" and r.config.get("replicate_source_db"):
        return  # replicas inherit the source's encryption
    value = r.config.get("storage_encrypted")
    if value is UNKNOWN or is_true(value):
        return
    yield Issue("storage_encrypted is not true", "storage_encrypted" if value is not None else None)


@rule(
    "AWS-RDS-002",
    "RDS instance is publicly accessible",
    H,
    ["aws_db_instance", "aws_rds_cluster_instance"],
    """publicly_accessible = true gives the database a public DNS name and IP,
    leaving only the security group between it and the internet.""",
    """publicly_accessible = false""",
    tags=["network"],
)
def rds_public(r: Resource, m: Module):
    if is_true(r.config.get("publicly_accessible")):
        yield Issue("publicly_accessible is true", "publicly_accessible")


@rule(
    "AWS-RDS-003",
    "RDS automated backups are disabled",
    M,
    ["aws_db_instance", "aws_rds_cluster"],
    """A backup retention period of 0 disables automated backups and
    point-in-time recovery.""",
    """backup_retention_period = 7  # or longer""",
    tags=["resilience"],
)
def rds_backups(r: Resource, m: Module):
    if r.config.get("backup_retention_period") == 0:
        yield Issue("backup_retention_period is 0", "backup_retention_period")


@rule(
    "AWS-REDSHIFT-001",
    "Redshift cluster is publicly accessible",
    H,
    ["aws_redshift_cluster"],
    """A publicly accessible Redshift cluster can be reached from the internet,
    leaving only the security group between the data warehouse and attackers.""",
    """publicly_accessible = false""",
    tags=["network"],
)
def redshift_public(r: Resource, m: Module):
    if is_true(r.config.get("publicly_accessible")):
        yield Issue("publicly_accessible is true", "publicly_accessible")


@rule(
    "AWS-EFS-001",
    "EFS file system is not encrypted",
    M,
    ["aws_efs_file_system"],
    """EFS encryption at rest can only be chosen at creation time.""",
    """encrypted = true""",
    tags=["encryption"],
)
def efs_encryption(r: Resource, m: Module):
    value = r.config.get("encrypted")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("encrypted is not true", "encrypted" if value is not None else None)


@rule(
    "AWS-OS-001",
    "OpenSearch domain is not encrypted at rest",
    M,
    ["aws_opensearch_domain", "aws_elasticsearch_domain"],
    """Search domains often hold copies of application logs and customer data.
    Encryption at rest protects indices, logs, swap files and snapshots.""",
    """encrypt_at_rest {
      enabled = true
    }""",
    tags=["encryption"],
)
def opensearch_encryption(r: Resource, m: Module):
    block = r.block("encrypt_at_rest")
    value = block.get("enabled") if block else None
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("encrypt_at_rest is not enabled", "encrypt_at_rest" if block else None)


@rule(
    "AWS-CACHE-001",
    "ElastiCache replication group does not encrypt traffic in transit",
    M,
    ["aws_elasticache_replication_group"],
    """Without in-transit encryption, Redis traffic including AUTH tokens and
    cached data crosses the network in clear text.""",
    """transit_encryption_enabled = true""",
    tags=["encryption"],
)
def elasticache_transit(r: Resource, m: Module):
    value = r.config.get("transit_encryption_enabled")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue(
            "transit_encryption_enabled is not true", "transit_encryption_enabled" if value is not None else None
        )


@rule(
    "AWS-SNS-001",
    "SNS topic is not encrypted",
    L,
    ["aws_sns_topic"],
    """Messages in an unencrypted topic are stored in plain text. Use a KMS key
    so access to message content is also controlled by key policy.""",
    """kms_master_key_id = "alias/aws/sns"  # or a customer managed key""",
    tags=["encryption"],
)
def sns_encryption(r: Resource, m: Module):
    if r.config.get("kms_master_key_id") in (None, ""):
        yield Issue("kms_master_key_id is not set")


@rule(
    "AWS-SQS-001",
    "SQS queue encryption is disabled",
    L,
    ["aws_sqs_queue"],
    """New queues use SQS-managed encryption by default; this queue explicitly
    turns it off and has no KMS key.""",
    """Remove sqs_managed_sse_enabled = false, or set kms_master_key_id.""",
    tags=["encryption"],
)
def sqs_encryption(r: Resource, m: Module):
    if is_false(r.config.get("sqs_managed_sse_enabled")) and r.config.get("kms_master_key_id") in (None, ""):
        yield Issue("sqs_managed_sse_enabled is false and no KMS key is set", "sqs_managed_sse_enabled")


@rule(
    "AWS-ECR-001",
    "ECR repository does not scan images on push",
    L,
    ["aws_ecr_repository"],
    """Scanning on push catches known-vulnerable packages before images are
    deployed.""",
    """image_scanning_configuration {
      scan_on_push = true
    }""",
    tags=["supply-chain"],
)
def ecr_scan(r: Resource, m: Module):
    block = r.block("image_scanning_configuration")
    value = block.get("scan_on_push") if block else None
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("scan_on_push is not enabled", "image_scanning_configuration" if block else None)


# ---------------------------------------------------------------------------
# Logging and keys
# ---------------------------------------------------------------------------


@rule(
    "AWS-CT-001",
    "CloudTrail trail is not multi-region",
    M,
    ["aws_cloudtrail"],
    """A single-region trail misses API activity in every other region, which
    is exactly where an attacker would spin up resources.""",
    """is_multi_region_trail = true""",
    tags=["logging"],
)
def cloudtrail_multi_region(r: Resource, m: Module):
    value = r.config.get("is_multi_region_trail")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("is_multi_region_trail is not true", "is_multi_region_trail" if value is not None else None)


@rule(
    "AWS-CT-002",
    "CloudTrail log file validation is disabled",
    M,
    ["aws_cloudtrail"],
    """Log file validation produces signed digest files, so tampering with or
    deleting log files can be detected.""",
    """enable_log_file_validation = true""",
    tags=["logging"],
)
def cloudtrail_validation(r: Resource, m: Module):
    value = r.config.get("enable_log_file_validation")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue(
            "enable_log_file_validation is not true", "enable_log_file_validation" if value is not None else None
        )


@rule(
    "AWS-CT-003",
    "CloudTrail logs are not encrypted with a KMS key",
    L,
    ["aws_cloudtrail"],
    """Encrypting trail logs with a customer managed KMS key adds a second access
    control: reading the logs also requires kms:Decrypt.""",
    """kms_key_id = aws_kms_key.cloudtrail.arn""",
    tags=["logging", "encryption"],
)
def cloudtrail_kms(r: Resource, m: Module):
    if r.config.get("kms_key_id") in (None, ""):
        yield Issue("kms_key_id is not set")


@rule(
    "AWS-KMS-001",
    "KMS key rotation is disabled",
    M,
    ["aws_kms_key"],
    """Automatic rotation limits how much data is protected by any one key
    version. It only applies to symmetric encryption keys.""",
    """enable_key_rotation = true""",
    tags=["encryption"],
)
def kms_rotation(r: Resource, m: Module):
    spec = r.config.get("customer_master_key_spec", "SYMMETRIC_DEFAULT")
    usage = r.config.get("key_usage", "ENCRYPT_DECRYPT")
    if spec not in ("SYMMETRIC_DEFAULT", None) or usage not in ("ENCRYPT_DECRYPT", None):
        return
    value = r.config.get("enable_key_rotation")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("enable_key_rotation is not true", "enable_key_rotation" if value is not None else None)


# ---------------------------------------------------------------------------
# Compute and edge services
# ---------------------------------------------------------------------------


@rule(
    "AWS-EKS-001",
    "EKS API endpoint is open to the internet",
    H,
    ["aws_eks_cluster"],
    """By default the Kubernetes API server endpoint is public and accepts
    connections from 0.0.0.0/0. Any leaked kubeconfig or API vulnerability
    is then exploitable from anywhere.""",
    """vpc_config {
      endpoint_private_access = true
      endpoint_public_access  = false  # or restrict public_access_cidrs
    }""",
    tags=["network"],
)
def eks_public(r: Resource, m: Module):
    for i, vpc in enumerate(r.blocks("vpc_config")):
        public = vpc.get("endpoint_public_access", True)
        if not (public is True or public is None):
            continue
        cidrs = vpc.get("public_access_cidrs")
        if cidrs is UNKNOWN:
            continue
        cidrs = as_list(cidrs) or ["0.0.0.0/0"]
        if any(is_public_cidr(c) for c in cidrs):
            yield Issue("Public endpoint accepts connections from 0.0.0.0/0", f"vpc_config[{i}]")


@rule(
    "AWS-ELB-001",
    "Load balancer listener serves plain HTTP",
    M,
    ["aws_lb_listener", "aws_alb_listener"],
    """An HTTP listener that forwards traffic (instead of redirecting to HTTPS)
    sends credentials and session cookies in clear text.""",
    """default_action {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }""",
    tags=["encryption", "network"],
)
def http_listener(r: Resource, m: Module):
    if r.config.get("protocol") != "HTTP":
        return
    actions = r.blocks("default_action")
    if any(a.get("type") in ("redirect", UNKNOWN) for a in actions):
        return
    yield Issue("HTTP listener does not redirect to HTTPS", "protocol")


_WEAK_TLS_POLICIES = {
    "ELBSecurityPolicy-2015-05",
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-TLS-1-1-2017-01",
    "ELBSecurityPolicy-FS-2018-06",
    "ELBSecurityPolicy-FS-1-1-2019-08",
    "ELBSecurityPolicy-TLS13-1-0-2021-06",
    "ELBSecurityPolicy-TLS13-1-1-2021-06",
}


@rule(
    "AWS-ELB-002",
    "Load balancer listener allows TLS 1.0 or 1.1",
    M,
    ["aws_lb_listener", "aws_alb_listener"],
    """TLS 1.0 and 1.1 are deprecated (RFC 8996). Older ELB security policies,
    including the historical default ELBSecurityPolicy-2016-08, still
    negotiate them.""",
    """ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06\"""",
    tags=["encryption"],
)
def weak_tls(r: Resource, m: Module):
    if r.config.get("protocol") not in ("HTTPS", "TLS"):
        return
    policy = r.config.get("ssl_policy")
    if policy is None:
        yield Issue("ssl_policy is not set, so the provider default (which allows TLS 1.0) applies")
    elif known(policy) and policy in _WEAK_TLS_POLICIES:
        yield Issue(f"ssl_policy {policy} allows TLS 1.0/1.1", "ssl_policy")


@rule(
    "AWS-LAMBDA-001",
    "Lambda function URL has no authentication",
    M,
    ["aws_lambda_function_url"],
    """authorization_type = "NONE" makes the function callable by anyone with
    the URL. That is sometimes intended for webhooks, but it should be a
    conscious, documented choice.""",
    """authorization_type = "AWS_IAM"  # or suppress with a reason if public by design""",
    tags=["authentication"],
)
def lambda_url(r: Resource, m: Module):
    if r.config.get("authorization_type") == "NONE":
        yield Issue('authorization_type is "NONE"', "authorization_type")
