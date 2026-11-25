variable "cfg" {
  type = object({
    name    = string
    ports   = optional(list(number), [22])
    tags    = optional(map(string), {})
  })
  default = { name = "x" }
  validation {
    condition     = length(var.cfg.name) > 0 && can(regex("^[a-z]+$", var.cfg.name))
    error_message = "Name must be lowercase."
  }
}

locals {
  subnets = { for idx, az in ["a", "b"] : az => cidrsubnet("10.0.0.0/16", 8, idx) } # trailing
  rendered = templatefile("${path.module}/user_data.sh.tpl", {
    env = "prod" /* inline */
  })
  msg = "100%% sure, %{ for s in ["a"] }${s}%{ endfor }"
  list = [
    "a", # comment between items
    // another
    "b",
  ]
  nested = jsonencode({
    a = <<-EOT
      inner ${upper("x")}
    EOT
  })
}

resource "aws_instance" "this" {
  for_each = toset(["a", "b"])
  ami      = data.aws_ami.al2023.id
  tags     = merge(var.cfg.tags, { Name = "web-${each.key}" })
  lifecycle {
    ignore_changes        = [tags["CreatedAt"], ami]
    create_before_destroy = true
    precondition {
      condition     = each.key != ""
      error_message = "x"
    }
  }
  metadata_options {
    http_tokens = "required"
  }
  user_data = local.rendered
  depends_on = [aws_iam_role.r]
}

moved {
  from = aws_instance.old
  to   = aws_instance.this["a"]
}

import {
  to = aws_s3_bucket.b
  id = "b"
}

check "health" {
  data "http" "h" {
    url = "https://example.com"
  }
  assert {
    condition     = data.http.h.status_code == 200
    error_message = "down"
  }
}

output "ids" {
  value     = [for k, v in aws_instance.this : v.id]
  sensitive = false
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
  count  = var.cfg.name == "x" ? 1 : 0
}
