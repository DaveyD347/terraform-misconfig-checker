variable "region" {
  type    = string
  default = "us-east-1"
}

variable "admin_cidr" {
  description = "Who may SSH to the bastion. Overridden in terraform.tfvars."
  type        = string
  default     = "10.0.0.0/8"
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "env" {
  type    = string
  default = "dev"
}
