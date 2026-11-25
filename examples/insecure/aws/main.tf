terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name = "acme-${var.env}"
  common_tags = {
    Project     = "acme"
    Environment = var.env
  }
  web_ports = [80, 443, 22]
}

# --- Storage ---------------------------------------------------------------

resource "aws_s3_bucket" "assets" {
  bucket = "${local.name}-assets"
  tags   = local.common_tags
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.assets.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name}-logs"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "${var.region}a"
  size              = 100
}

# --- Network ---------------------------------------------------------------

resource "aws_security_group" "web" {
  name        = "${local.name}-web"
  description = "Web tier"

  dynamic "ingress" {
    for_each = local.web_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "bastion_ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
}

resource "aws_vpc_security_group_ingress_rule" "debug_everything" {
  security_group_id = aws_security_group.web.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "db" {
  name = "${local.name}-db"

  ingress {
    description = "Postgres from anywhere (for the BI tool)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Compute ---------------------------------------------------------------

resource "aws_instance" "web" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]

  root_block_device {
    volume_size = 20
  }

  metadata_options {
    http_tokens = "optional"
  }
}

# --- Databases -------------------------------------------------------------

resource "aws_db_instance" "main" {
  identifier              = "${local.name}-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "app"
  password                = var.db_password
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
  skip_final_snapshot     = true
}

# --- IAM -------------------------------------------------------------------

data "aws_iam_policy_document" "ci_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = "${local.name}-ci"
  assume_role_policy = data.aws_iam_policy_document.ci_assume.json
}

resource "aws_iam_role_policy_attachment" "ci_admin" {
  role       = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy" "deployer" {
  name = "${local.name}-deployer"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:*", "dynamodb:GetItem"]
        Resource = aws_s3_bucket.logs.arn
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "bob" {
  user       = "bob"
  policy_arn = aws_iam_policy.deployer.arn
}

# --- Logging and keys ------------------------------------------------------

resource "aws_kms_key" "app" {
  description = "Application data key"
}

resource "aws_cloudtrail" "main" {
  name           = "${local.name}-trail"
  s3_bucket_name = aws_s3_bucket.logs.id
}

# --- Edge ------------------------------------------------------------------

resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme/abc"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/acme/def"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme/abc"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:111122223333:certificate/1234"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/acme/def"
  }
}

resource "aws_eks_cluster" "main" {
  name     = "${local.name}-eks"
  role_arn = aws_iam_role.ci.arn

  vpc_config {
    subnet_ids = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
  }
}

resource "aws_lambda_function_url" "webhook" {
  # tfcheck:ignore=AWS-LAMBDA-001 Public by design: Stripe webhook, payload signature is verified in code
  function_name      = "acme-stripe-webhook"
  authorization_type = "NONE"
}

resource "aws_sqs_queue" "jobs" {
  name                    = "${local.name}-jobs"
  sqs_managed_sse_enabled = false
}
