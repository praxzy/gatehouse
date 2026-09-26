resource "aws_security_group" "application" {
  name        = "${local.name_prefix}-application"
  description = "Gatehouse application workload traffic"
  vpc_id      = aws_vpc.this.id

  revoke_rules_on_delete = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-application"
      Tier = "application"
    },
  )
}

resource "aws_security_group" "database" {
  name        = "${local.name_prefix}-database"
  description = "Gatehouse PostgreSQL traffic from application workloads"
  vpc_id      = aws_vpc.this.id

  revoke_rules_on_delete = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-database"
      Tier = "database"
    },
  )
}

resource "aws_vpc_security_group_ingress_rule" "database_from_application" {
  security_group_id = aws_security_group.database.id

  referenced_security_group_id = aws_security_group.application.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432

  description = "PostgreSQL from Gatehouse application workloads"
}

resource "aws_vpc_security_group_egress_rule" "application_to_database" {
  security_group_id = aws_security_group.application.id

  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432

  description = "PostgreSQL to Gatehouse RDS"
}

resource "aws_vpc_security_group_egress_rule" "application_https" {
  security_group_id = aws_security_group.application.id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  description = "HTTPS for AWS APIs and external identity providers"
}

resource "aws_vpc_security_group_egress_rule" "application_dns_udp" {
  security_group_id = aws_security_group.application.id

  cidr_ipv4   = var.vpc_cidr
  ip_protocol = "udp"
  from_port   = 53
  to_port     = 53

  description = "DNS through the VPC resolver"
}

resource "aws_vpc_security_group_egress_rule" "application_dns_tcp" {
  security_group_id = aws_security_group.application.id

  cidr_ipv4   = var.vpc_cidr
  ip_protocol = "tcp"
  from_port   = 53
  to_port     = 53

  description = "DNS fallback through the VPC resolver"
}