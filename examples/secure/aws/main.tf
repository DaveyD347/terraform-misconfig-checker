# A hardened baseline: tfcheck reports no findings here.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "office_cidr" {
  type    = string
  default = "203.0.113.0/24"
}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "data" {
  description         = "Data encryption key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "acme-prod-data"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.tls_only.json
}

data "aws_iam_policy_document" "tls_only" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_db_instance" "main" {
  identifier                  = "acme-prod"
  engine                      = "postgres"
  instance_class              = "db.t3.medium"
  allocated_storage           = 50
  username                    = "app"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.data.arn
  publicly_accessible         = false
  backup_retention_period     = 14
  deletion_protection         = true
}

data "aws_iam_policy_document" "app" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }
}

resource "aws_iam_policy" "app" {
  name   = "app"
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = "acme-audit-logs"
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.data.arn
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme/abc"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme/abc"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:111122223333:certificate/1234"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/acme/def"
  }
}

resource "aws_eks_cluster" "main" {
  name     = "acme-prod"
  role_arn = "arn:aws:iam::111122223333:role/eks-cluster"

  vpc_config {
    subnet_ids              = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
