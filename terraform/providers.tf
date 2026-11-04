# Which Terraform and which AWS provider version this project needs.
terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # Zips the app code (api/, dal/, logic/) for upload to S3.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# Credentials come from `aws configure` (~/.aws/credentials), never from code.
provider "aws" {
  region = var.aws_region

  # Added to every resource, so the whole project is easy to find and bill.
  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
    }
  }
}
