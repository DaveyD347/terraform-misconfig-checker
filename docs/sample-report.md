## Terraform misconfiguration report

| Severity | Findings |
|---|---:|
| 🟣 Critical | 5 |
| 🔴 High | 17 |
| 🟠 Medium | 17 |
| 🔵 Low | 8 |

Scanned **44** resources in **4** module(s) with **46** rules. 47 finding(s), 1 suppressed.

| Severity | Rule | Resource | Location | Issue |
|---|---|---|---|---|
| 🟣 critical | `AWS-EC2-001` | `aws_vpc_security_group_ingress_rule.debug_everything` | `examples/insecure/aws/main.tf:101` | Security group allows ingress from the internet to sensitive ports: Ingress from ::/0 to all ports |
| 🟣 critical | `AWS-IAM-004` | `aws_iam_role.ci` | `examples/insecure/aws/main.tf:163` | IAM role can be assumed by any principal: Trust policy allows Principal "*" without a condition |
| 🟣 critical | `AWS-IAM-001` | `aws_iam_policy.deployer` | `examples/insecure/aws/main.tf:173` | IAM policy grants full administrator access: Statement allows Action "*" on Resource "*" |
| 🟣 critical | `AZ-NET-001` | `azurerm_network_security_rule.any_any` | `examples/insecure/azure/main.tf:68` | Network security group allows inbound internet traffic to sensitive ports: Rule "temp-allow-all" allows inbound from 0.0.0.0/0 to all ports |
| 🟣 critical | `AWS-IAM-001` | `aws_iam_policy.etl` | `examples/plan/tfplan.json` | IAM policy grants full administrator access: Statement allows Action "*" on Resource "*" |
| 🔴 high | `AWS-S3-001` | `aws_s3_bucket_acl.assets` | `examples/insecure/aws/main.tf:32` | S3 bucket ACL grants public access: Bucket ACL is "public-read" |
| 🔴 high | `AWS-S3-003` | `aws_s3_bucket_policy.assets` | `examples/insecure/aws/main.tf:45` | S3 bucket policy allows access from any principal: Statement allows s3:GetObject to Principal "*" with no condition |
| 🔴 high | `AWS-EC2-001` | `aws_security_group.web` | `examples/insecure/aws/main.tf:74` | Security group allows ingress from the internet to sensitive ports: Ingress from 0.0.0.0/0 to 22 (SSH) |
| 🔴 high | `AWS-EC2-001` | `aws_security_group_rule.bastion_ssh` | `examples/insecure/aws/main.tf:96` | Security group allows ingress from the internet to sensitive ports: Ingress from 0.0.0.0/0 to 22 (SSH) |
| 🔴 high | `AWS-EC2-001` | `aws_security_group.db` | `examples/insecure/aws/main.tf:108` | Security group allows ingress from the internet to sensitive ports: Ingress from 0.0.0.0/0 to 5432 (PostgreSQL) |
| 🔴 high | `AWS-RDS-002` | `aws_db_instance.main` | `examples/insecure/aws/main.tf:143` | RDS instance is publicly accessible: publicly_accessible is true |
| 🔴 high | `AWS-RDS-001` | `aws_db_instance.main` | `examples/insecure/aws/main.tf:144` | RDS storage is not encrypted: storage_encrypted is not true |
| 🔴 high | `AWS-IAM-003` | `aws_iam_role_policy_attachment.ci_admin` | `examples/insecure/aws/main.tf:168` | AdministratorAccess managed policy is attached: Attaches arn:aws:iam::aws:policy/AdministratorAccess |
| 🔴 high | `AWS-EKS-001` | `aws_eks_cluster.main` | `examples/insecure/aws/main.tf:236` | EKS API endpoint is open to the internet: Public endpoint accepts connections from 0.0.0.0/0 |
| 🔴 high | `AZ-STORAGE-001` | `azurerm_storage_account.exports` | `examples/insecure/azure/main.tf:25` | Storage account allows public blob containers: allow_nested_items_to_be_public is true |
| 🔴 high | `AZ-STORAGE-002` | `azurerm_storage_account.exports` | `examples/insecure/azure/main.tf:26` | Storage account accepts plain HTTP: https_traffic_only_enabled is false |
| 🔴 high | `AZ-NET-001` | `azurerm_network_security_group.vm` | `examples/insecure/azure/main.tf:35` | Network security group allows inbound internet traffic to sensitive ports: Rule "allow-rdp" allows inbound from * to 3389 (RDP) |
| 🔴 high | `AZ-SQL-001` | `azurerm_mssql_firewall_rule.everyone` | `examples/insecure/azure/main.tf:91` | Database firewall rule allows the entire internet: Firewall rule covers 0.0.0.0 - 255.255.255.255 |
| 🔴 high | `GCP-STORAGE-001` | `google_storage_bucket_iam_member.public_read` | `examples/insecure/gcp/main.tf:23` | Cloud Storage bucket is publicly accessible: Grants roles/storage.objectViewer to allUsers |
| 🔴 high | `GCP-NET-001` | `google_compute_firewall.ssh` | `examples/insecure/gcp/main.tf:30` | Firewall rule allows internet traffic to sensitive ports: Allows tcp from 0.0.0.0/0 to 22 (SSH) |
| 🔴 high | `GCP-SQL-001` | `google_sql_database_instance.main` | `examples/insecure/gcp/main.tf:59` | Cloud SQL instance is open to the internet: Authorized network 0.0.0.0/0 allows the whole internet |
| 🔴 high | `AWS-EC2-001` | `module.app.aws_security_group.this[0]` | `examples/plan/tfplan.json` | Security group allows ingress from the internet to sensitive ports: Ingress from 0.0.0.0/0 to 3389 (RDP) |
| 🟠 medium | `AWS-S3-002` | `aws_s3_bucket.assets` | `examples/insecure/aws/main.tf:25` | S3 bucket is not covered by a full public access block: Public access block aws_s3_bucket_public_access_block.assets leaves block_public_acls, block_public_policy disabled |
| 🟠 medium | `AWS-S3-002` | `aws_s3_bucket.logs` | `examples/insecure/aws/main.tf:57` | S3 bucket is not covered by a full public access block: No aws_s3_bucket_public_access_block is attached to this bucket |
| 🟠 medium | `AWS-EC2-002` | `aws_ebs_volume.data` | `examples/insecure/aws/main.tf:61` | EBS storage is not encrypted: Volume is not encrypted |
| 🟠 medium | `AWS-EC2-003` | `aws_instance.web` | `examples/insecure/aws/main.tf:119` | Instance metadata service allows IMDSv1: http_tokens is "optional" |
| 🟠 medium | `AWS-EC2-002` | `aws_instance.web` | `examples/insecure/aws/main.tf:125` | EBS storage is not encrypted: Root block device is not encrypted |
| 🟠 medium | `AWS-RDS-003` | `aws_db_instance.main` | `examples/insecure/aws/main.tf:145` | RDS automated backups are disabled: backup_retention_period is 0 |
| 🟠 medium | `AWS-IAM-002` | `aws_iam_policy.deployer` | `examples/insecure/aws/main.tf:173` | IAM policy uses service-wide wildcard actions: Statement allows s3:* |
| 🟠 medium | `AWS-KMS-001` | `aws_kms_key.app` | `examples/insecure/aws/main.tf:197` | KMS key rotation is disabled: enable_key_rotation is not true |
| 🟠 medium | `AWS-CT-001` | `aws_cloudtrail.main` | `examples/insecure/aws/main.tf:201` | CloudTrail trail is not multi-region: is_multi_region_trail is not true |
| 🟠 medium | `AWS-CT-002` | `aws_cloudtrail.main` | `examples/insecure/aws/main.tf:201` | CloudTrail log file validation is disabled: enable_log_file_validation is not true |
| 🟠 medium | `AWS-ELB-001` | `aws_lb_listener.http` | `examples/insecure/aws/main.tf:211` | Load balancer listener serves plain HTTP: HTTP listener does not redirect to HTTPS |
| 🟠 medium | `AWS-ELB-002` | `aws_lb_listener.https` | `examples/insecure/aws/main.tf:223` | Load balancer listener allows TLS 1.0 or 1.1: ssl_policy ELBSecurityPolicy-2016-08 allows TLS 1.0/1.1 |
| 🟠 medium | `AZ-STORAGE-003` | `azurerm_storage_account.exports` | `examples/insecure/azure/main.tf:27` | Storage account allows TLS versions older than 1.2: min_tls_version is TLS1_0 |
| 🟠 medium | `GCP-SQL-002` | `google_sql_database_instance.main` | `examples/insecure/gcp/main.tf:56` | Cloud SQL instance does not require SSL: Public IP is enabled and SSL is not enforced |
| 🟠 medium | `GCP-IAM-002` | `google_project_iam_member.contractor` | `examples/insecure/gcp/main.tf:69` | Primitive owner or editor role is granted: Grants roles/editor |
| 🟠 medium | `GCP-COMPUTE-001` | `google_compute_instance.worker` | `examples/insecure/gcp/main.tf:88` | Instance uses the default service account with full API access: Default service account with the cloud-platform scope |
| 🟠 medium | `AWS-S3-002` | `aws_s3_bucket.reports` | `examples/plan/tfplan.json` | S3 bucket is not covered by a full public access block: Public access block aws_s3_bucket_public_access_block.reports leaves restrict_public_buckets disabled |
| 🔵 low | `AWS-S3-004` | `aws_s3_bucket.assets` | `examples/insecure/aws/main.tf:25` | S3 bucket versioning is not enabled: Versioning is not enabled for this bucket |
| 🔵 low | `AWS-S3-004` | `aws_s3_bucket.logs` | `examples/insecure/aws/main.tf:57` | S3 bucket versioning is not enabled: Versioning is not enabled for this bucket |
| 🔵 low | `AWS-EC2-004` | `aws_instance.web` | `examples/insecure/aws/main.tf:122` | Instance gets a public IP address: associate_public_ip_address is true |
| 🔵 low | `AWS-IAM-005` | `aws_iam_user_policy_attachment.bob` | `examples/insecure/aws/main.tf:190` | IAM policy is attached directly to a user: Policy is attached to an IAM user instead of a group or role |
| 🔵 low | `AWS-CT-003` | `aws_cloudtrail.main` | `examples/insecure/aws/main.tf:201` | CloudTrail logs are not encrypted with a KMS key: kms_key_id is not set |
| 🔵 low | `AWS-SQS-001` | `aws_sqs_queue.jobs` | `examples/insecure/aws/main.tf:249` | SQS queue encryption is disabled: sqs_managed_sse_enabled is false and no KMS key is set |
| 🔵 low | `AZ-KV-001` | `azurerm_key_vault.main` | `examples/insecure/azure/main.tf:97` | Key Vault purge protection is disabled: purge_protection_enabled is not true |
| 🔵 low | `GCP-STORAGE-002` | `google_storage_bucket.public_site` | `examples/insecure/gcp/main.tf:15` | Cloud Storage bucket does not use uniform bucket-level access: uniform_bucket_level_access is not true |

<details><summary>How to fix</summary>

#### AWS-CT-001: CloudTrail trail is not multi-region

A single-region trail misses API activity in every other region, which is exactly where an attacker would spin up resources.

```hcl
is_multi_region_trail = true
```

#### AWS-CT-002: CloudTrail log file validation is disabled

Log file validation produces signed digest files, so tampering with or deleting log files can be detected.

```hcl
enable_log_file_validation = true
```

#### AWS-CT-003: CloudTrail logs are not encrypted with a KMS key

Encrypting trail logs with a customer managed KMS key adds a second access control: reading the logs also requires kms:Decrypt.

```hcl
kms_key_id = aws_kms_key.cloudtrail.arn
```

#### AWS-EC2-001: Security group allows ingress from the internet to sensitive ports

Remote administration (SSH, RDP, WinRM, VNC) and database or cache ports open to 0.0.0.0/0 or ::/0 are scanned constantly and brute-forced within minutes. Rules that open every port are reported as critical.

Restrict the source to known CIDR ranges or another security group, and reach instances through SSM Session Manager or a bastion instead of exposing admin ports.

```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.20.0.0/16"]
}
```

#### AWS-EC2-002: EBS storage is not encrypted

Unencrypted EBS volumes and snapshots expose data to anyone who gains access to a snapshot copy or the underlying storage. Encryption is free and has no meaningful performance cost.

Set encrypted = true on volumes and block device mappings, or turn on account-wide default encryption:

```hcl
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}
```

#### AWS-EC2-003: Instance metadata service allows IMDSv1

IMDSv1 answers unauthenticated GET requests, so any SSRF bug in an application on the instance can be used to steal its IAM role credentials. IMDSv2 requires a session token and blocks this.

```hcl
metadata_options {
  http_endpoint = "enabled"
  http_tokens   = "required"
}
```

#### AWS-EC2-004: Instance gets a public IP address

Instances with public IPs are directly reachable from the internet, so a single security group mistake exposes them. Put workloads in private subnets behind a load balancer or NAT.

Remove associate_public_ip_address (or set it to false) and place the instance in a private subnet.

#### AWS-EKS-001: EKS API endpoint is open to the internet

By default the Kubernetes API server endpoint is public and accepts connections from 0.0.0.0/0. Any leaked kubeconfig or API vulnerability is then exploitable from anywhere.

```hcl
vpc_config {
  endpoint_private_access = true
  endpoint_public_access  = false  # or restrict public_access_cidrs
}
```

#### AWS-ELB-001: Load balancer listener serves plain HTTP

An HTTP listener that forwards traffic (instead of redirecting to HTTPS) sends credentials and session cookies in clear text.

```hcl
default_action {
  type = "redirect"
  redirect {
    port        = "443"
    protocol    = "HTTPS"
    status_code = "HTTP_301"
  }
}
```

#### AWS-ELB-002: Load balancer listener allows TLS 1.0 or 1.1

TLS 1.0 and 1.1 are deprecated (RFC 8996). Older ELB security policies, including the historical default ELBSecurityPolicy-2016-08, still negotiate them.

```hcl
ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
```

#### AWS-IAM-001: IAM policy grants full administrator access

A statement allowing Action "*" on Resource "*" is full admin. Anyone or anything that can use this policy can disable logging, create users and take over the account.

Grant only the actions and resources the workload needs. IAM Access Analyzer can generate a least-privilege policy from CloudTrail activity.

#### AWS-IAM-002: IAM policy uses service-wide wildcard actions

Actions such as "s3:*" or "iam:*", or an Allow with NotAction, grant every current and future permission of a service, including destructive and privilege-escalation actions.

List the specific actions needed, for example ["s3:GetObject", "s3:PutObject"] instead of "s3:*".

#### AWS-IAM-003: AdministratorAccess managed policy is attached

The AWS managed AdministratorAccess policy grants every action on every resource. Attaching it to roles used by workloads or CI turns any compromise of that workload into a full account takeover.

Attach a scoped customer managed policy instead, and reserve administrator access for break-glass roles protected by MFA.

#### AWS-IAM-004: IAM role can be assumed by any principal

A trust policy that allows Principal "*" (or AWS "*") to call sts:AssumeRole without a condition lets any AWS account in the world assume the role.

Trust specific accounts, roles or services, and require sts:ExternalId or aws:PrincipalOrgID conditions for cross-account access.

#### AWS-IAM-005: IAM policy is attached directly to a user

Permissions granted to individual users are hard to audit and tend to outlive the person's role. Grant permissions to groups or roles.

Attach the policy to an aws_iam_group and add the user to the group, or move humans to IAM Identity Center.

#### AWS-KMS-001: KMS key rotation is disabled

Automatic rotation limits how much data is protected by any one key version. It only applies to symmetric encryption keys.

```hcl
enable_key_rotation = true
```

#### AWS-RDS-001: RDS storage is not encrypted

Unencrypted database storage, snapshots and read replicas expose data at rest. Encryption can only be enabled when the database is created, so it is expensive to fix later.

```hcl
storage_encrypted = true
kms_key_id        = aws_kms_key.rds.arn  # optional customer managed key
```

#### AWS-RDS-002: RDS instance is publicly accessible

publicly_accessible = true gives the database a public DNS name and IP, leaving only the security group between it and the internet.

```hcl
publicly_accessible = false
```

#### AWS-RDS-003: RDS automated backups are disabled

A backup retention period of 0 disables automated backups and point-in-time recovery.

```hcl
backup_retention_period = 7  # or longer
```

#### AWS-S3-001: S3 bucket ACL grants public access

A canned ACL of public-read, public-read-write or authenticated-read lets anyone on the internet (or any AWS account) list or modify objects. Public ACLs are the classic cause of S3 data leaks.

Use a private ACL (or disable ACLs entirely with object ownership "BucketOwnerEnforced") and serve public content through CloudFront with origin access control instead.

```hcl
resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
```

#### AWS-S3-002: S3 bucket is not covered by a full public access block

S3 Block Public Access is the guard rail that stops a future ACL or bucket policy change from exposing data. Every bucket should have all four settings enabled, either on the bucket or account-wide.

```hcl
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

#### AWS-S3-003: S3 bucket policy allows access from any principal

A bucket policy statement with Effect Allow and Principal "*" and no Condition grants that access to everyone on the internet.

Name the specific AWS principals that need access, or add a Condition (for example aws:SourceVpce, aws:PrincipalOrgID or aws:SourceArn) that narrows who can use the statement.

#### AWS-S3-004: S3 bucket versioning is not enabled

Without versioning, an overwritten or deleted object is gone for good, which turns ransomware or a bad deploy script into permanent data loss.

```hcl
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration { status = "Enabled" }
}
```

#### AWS-SQS-001: SQS queue encryption is disabled

New queues use SQS-managed encryption by default; this queue explicitly turns it off and has no KMS key.

Remove sqs_managed_sse_enabled = false, or set kms_master_key_id.

#### AZ-KV-001: Key Vault purge protection is disabled

Without purge protection, anyone with sufficient rights can permanently delete the vault and its keys during the soft-delete period, which can make encrypted data unrecoverable.

```hcl
purge_protection_enabled = true
```

#### AZ-NET-001: Network security group allows inbound internet traffic to sensitive ports

An Allow rule from "*", "Internet" or 0.0.0.0/0 to SSH, RDP, WinRM or database ports exposes them to constant scanning and brute force. Rules that open every port are reported as critical.

Limit source_address_prefix to known ranges, and use Azure Bastion or just-in-time VM access for administration.

#### AZ-SQL-001: Database firewall rule allows the entire internet

A firewall rule from 0.0.0.0 to 255.255.255.255 lets every IP address on the internet attempt to log in to the database server.

Allow only the client ranges that need access, or use private endpoints.

#### AZ-STORAGE-001: Storage account allows public blob containers

allow_nested_items_to_be_public = true lets any container in the account be switched to anonymous public read access.

```hcl
allow_nested_items_to_be_public = false
```

#### AZ-STORAGE-002: Storage account accepts plain HTTP

With HTTPS-only disabled, storage requests (including SAS tokens in the URL) can travel unencrypted.

```hcl
https_traffic_only_enabled = true  # enable_https_traffic_only on azurerm < 4.0
```

#### AZ-STORAGE-003: Storage account allows TLS versions older than 1.2

TLS 1.0 and 1.1 are deprecated and Azure is retiring support for them.

```hcl
min_tls_version = "TLS1_2"
```

#### GCP-COMPUTE-001: Instance uses the default service account with full API access

The Compute Engine default service account has the Editor role in many projects. Combined with the cloud-platform scope, any code running on the VM can manage most of the project.

Create a dedicated service account with only the roles the workload needs, and attach it with that email.

#### GCP-IAM-002: Primitive owner or editor role is granted

The basic Owner and Editor roles include thousands of permissions across every service. Google recommends predefined or custom roles instead.

Replace roles/owner and roles/editor with predefined roles scoped to the services the identity uses.

#### GCP-NET-001: Firewall rule allows internet traffic to sensitive ports

An ingress rule from 0.0.0.0/0 to SSH, RDP or database ports exposes every matching instance to the internet. Rules that allow every port are reported as critical.

Restrict source_ranges, and use Identity-Aware Proxy TCP forwarding (35.235.240.0/20) for SSH and RDP.

#### GCP-SQL-001: Cloud SQL instance is open to the internet

An authorized network of 0.0.0.0/0 lets any IP address connect to the instance's public IP and try to log in.

Remove the 0.0.0.0/0 authorized network; use private IP or the Cloud SQL Auth Proxy instead.

#### GCP-SQL-002: Cloud SQL instance does not require SSL

Unless SSL is enforced, clients can connect to the public IP over an unencrypted connection.

```hcl
settings {
  ip_configuration {
    ssl_mode = "ENCRYPTED_ONLY"
  }
}
```

#### GCP-STORAGE-001: Cloud Storage bucket is publicly accessible

Granting a role to allUsers or allAuthenticatedUsers makes the bucket readable (or writable) by anyone with a Google account or no account at all.

Grant roles to specific users, groups or service accounts. Enable public access prevention on the bucket:

```hcl
public_access_prevention = "enforced"
```

#### GCP-STORAGE-002: Cloud Storage bucket does not use uniform bucket-level access

With fine-grained ACLs, individual objects can be made public even when bucket IAM looks locked down. Uniform bucket-level access makes IAM the only access control.

```hcl
uniform_bucket_level_access = true
```

</details>

<details><summary>Suppressed findings</summary>

| Rule | Resource | Reason |
|---|---|---|
| `AWS-LAMBDA-001` | `aws_lambda_function_url.webhook` | Public by design: Stripe webhook, payload signature is verified in code |

</details>
