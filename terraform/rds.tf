# The RDS instance was created by hand. Terraform only READS it here (data source),
# so it can never change or destroy it.
data "aws_db_instance" "main" {
  db_instance_identifier = var.db_identifier
}

locals {
  db_host       = data.aws_db_instance.main.address
  db_port       = data.aws_db_instance.main.port
  db_name       = data.aws_db_instance.main.db_name
  db_secret_arn = data.aws_db_instance.main.master_user_secret[0].secret_arn
}
