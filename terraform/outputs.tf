# Printed after `terraform apply`; you'll need the db_* values in the RDS console.

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "db_subnet_group_name" {
  description = "Pick this as the DB subnet group when creating RDS."
  value       = aws_db_subnet_group.main.name
}

output "db_security_group" {
  description = "Pick this as the only security group when creating RDS."
  value       = aws_security_group.db.name
}

output "nat_public_ips" {
  value = aws_eip.nat[*].public_ip
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "db_security_group_id" {
  value = aws_security_group.db.id
}

output "app_url" {
  description = "Open this in a browser once the instances are healthy."
  value       = "https://${aws_cloudfront_distribution.app.domain_name}"
}

output "alb_url" {
  description = "Old direct ALB URL. No longer reachable (403 / blocked by the security group)."
  value       = "http://${aws_lb.app.dns_name}"
}

output "asg_name" {
  value = aws_autoscaling_group.app.name
}

output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.id
}
