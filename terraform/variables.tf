variable "aws_region" {
  description = "AWS region for every resource."
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Prefix for resource names."
  type        = string
  default     = "phishing-detector"
}

variable "vpc_cidr" {
  description = "Address range of the whole VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnets (ALB, NAT), one per AZ."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Private subnets (EC2, RDS, ElastiCache), one per AZ."
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "single_nat_gateway" {
  description = "true: one NAT for both AZs (cheaper). false: one NAT per AZ (highly available outbound)."
  type        = bool
  default     = true
}

variable "app_port" {
  description = "Port the web app listens on inside the EC2 instances."
  type        = number
  default     = 8000
}

variable "db_identifier" {
  description = "Identifier of the existing RDS instance (created by hand; Terraform only reads it)."
  type        = string
  default     = "phishing-detector-db"
}

variable "instance_type" {
  description = "EC2 instance type for the app servers."
  type        = string
  default     = "t3.micro"
}

variable "alert_email" {
  description = "Email that receives CloudWatch alarm notifications (pass with -var; must confirm the SNS subscription)."
  type        = string
}
