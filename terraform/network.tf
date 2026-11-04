# ---------------------------------------------------------------------------
# VPC: the private network everything lives in.
# ---------------------------------------------------------------------------

# The first two availability zones of the region (e.g. eu-west-1a, eu-west-1b).
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs       = slice(data.aws_availability_zones.available.names, 0, 2)
  nat_count = var.single_nat_gateway ? 1 : 2
}

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Needed so names like the RDS endpoint resolve inside the VPC.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# The VPC's door to the internet (used by the public subnets only).
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# ---------------------------------------------------------------------------
# Subnets: 2 public + 2 private, each pair split across 2 AZs.
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  # Anything launched here (ALB, NAT, a bastion) gets a public IP, so it can
  # actually use the Internet Gateway route.
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.project_name}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# ---------------------------------------------------------------------------
# Routing: public subnets go out through the Internet Gateway,
# private subnets go out (only outbound!) through the NAT Gateway.
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# NAT lets private EC2 instances reach out (pip install, AWS APIs)
# while nobody on the internet can reach in.
resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"
  tags   = { Name = "${var.project_name}-nat-eip-${count.index}" }
}

resource "aws_nat_gateway" "main" {
  count         = local.nat_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id # a NAT lives in a PUBLIC subnet

  tags       = { Name = "${var.project_name}-nat-${count.index}" }
  depends_on = [aws_internet_gateway.main]
}

# One route table per private subnet, so each AZ can use its own NAT
# when single_nat_gateway = false.
resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
  }

  tags = { Name = "${var.project_name}-private-rt-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# DB Subnet Group: where RDS is ALLOWED to live (both private subnets).
# RDS itself is created by hand in the console and picks this group.
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name        = "${var.project_name}-db-subnets"
  description = "Private subnets for the RDS instance"
  subnet_ids  = aws_subnet.private[*].id

  tags = { Name = "${var.project_name}-db-subnets" }
}

# ---------------------------------------------------------------------------
# Secrets Manager VPC endpoint: the app reads its DB credentials at startup
# and on secret rotation, so this must not depend on the (single) NAT gateway.
# ---------------------------------------------------------------------------

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${var.project_name}-secretsmanager-endpoint" }
}
