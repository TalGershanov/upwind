# ---------------------------------------------------------------------------
# Security Groups = firewalls. Tiered: internet -> ALB -> EC2 -> RDS / cache.
# Each tier accepts traffic ONLY from the tier above it.
# (Terraform removes AWS's default "allow all outbound" rule, so a group
# has no outbound access unless a rule below grants it.)
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "ALB: HTTP from the internet, forwards to the app"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-alb-sg" }
}

resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "EC2 app servers: traffic from the ALB only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-app-sg" }
}

resource "aws_security_group" "db" {
  name        = "${var.project_name}-db-sg"
  description = "RDS PostgreSQL: traffic from the app servers only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-db-sg" }
}

resource "aws_security_group" "cache" {
  name        = "${var.project_name}-cache-sg"
  description = "ElastiCache: traffic from the app servers only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-cache-sg" }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project_name}-vpce-sg"
  description = "VPC interface endpoints: HTTPS from the app servers only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project_name}-vpce-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "vpce_from_app" {
  security_group_id            = aws_security_group.vpc_endpoints.id
  description                  = "HTTPS from the app servers only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# --- ALB ---------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "alb_http_from_internet" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward requests and health checks to the app"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

# --- App (EC2) ---------------------------------------------------------------
# No SSH port at all: we connect with SSM Session Manager instead.

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Requests from the ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

resource "aws_vpc_security_group_egress_rule" "app_https_out" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS out via NAT: AWS APIs (Secrets Manager, CloudWatch, SSM) and package installs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL to RDS"
  referenced_security_group_id = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "app_to_cache" {
  security_group_id            = aws_security_group.app.id
  description                  = "Valkey/Redis to ElastiCache (6379 primary, 6380 replica reads)"
  referenced_security_group_id = aws_security_group.cache.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6380
}

# --- RDS ---------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the app servers only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# --- ElastiCache -------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "cache_from_app" {
  security_group_id            = aws_security_group.cache.id
  description                  = "Valkey/Redis from the app servers only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6380
}
