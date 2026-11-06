data "aws_caller_identity" "current" {}

# --- Private bucket that holds the app zip -----------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project_name}-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # lets `terraform destroy` delete it even when it holds files
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- The app zip: ONLY api/, dal/, logic/, logging_config.py and requirements.txt ----------------
# archive_file can't zip several folders at once, so we list the files ourselves.
# "**" takes every file (including api/static/index.html); __pycache__ and
# macOS .DS_Store files are skipped.

locals {
  repo_root = "${path.module}/.."
  app_files = setunion(
    [for f in fileset(local.repo_root, "{api,dal,logic}/**") : f if !strcontains(f, "__pycache__") && !endswith(f, ".DS_Store")],
    ["requirements.txt", "logging_config.py"],
  )
}

data "archive_file" "app" {
  type        = "zip"
  output_path = "${path.module}/build/app.zip"

  dynamic "source" {
    for_each = local.app_files
    content {
      filename = source.value
      content  = file("${local.repo_root}/${source.value}")
    }
  }
}

# The zip's hash is in the key: new code = new key = new launch template version,
# which makes the ASG roll the instances.
resource "aws_s3_object" "app" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "app-${substr(data.archive_file.app.output_sha256, 0, 12)}.zip"
  source = data.archive_file.app.output_path
  etag   = data.archive_file.app.output_md5
}
