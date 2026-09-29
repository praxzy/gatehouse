resource "aws_security_group" "load_balancer" {
  name        = "${local.name}-alb"
  description = "Public traffic to the Gatehouse application load balancer"
  vpc_id      = var.vpc_id

  revoke_rules_on_delete = true

  tags = merge(local.common_tags, {
    Name = "${local.name}-alb"
    Tier = "edge"
  })

  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.certificate_arn != null
      error_message = "Production requires an ACM certificate ARN."
    }
  }
}

resource "aws_security_group" "api_service" {
  name        = "${local.name}-api"
  description = "Traffic from the Gatehouse ALB to API tasks"
  vpc_id      = var.vpc_id

  revoke_rules_on_delete = true

  tags = merge(local.common_tags, {
    Name = "${local.name}-api"
    Tier = "application"
  })
}

resource "aws_vpc_security_group_ingress_rule" "load_balancer_http" {
  for_each = var.allowed_ingress_cidrs

  security_group_id = aws_security_group.load_balancer.id

  cidr_ipv4   = each.value
  ip_protocol = "tcp"
  from_port   = 80
  to_port     = 80

  description = "HTTP from approved public networks"
}

resource "aws_vpc_security_group_ingress_rule" "load_balancer_https" {
  for_each = var.certificate_arn == null ? toset([]) : var.allowed_ingress_cidrs

  security_group_id = aws_security_group.load_balancer.id

  cidr_ipv4   = each.value
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  description = "HTTPS from approved public networks"
}

resource "aws_vpc_security_group_egress_rule" "load_balancer_to_api" {
  security_group_id = aws_security_group.load_balancer.id

  referenced_security_group_id = aws_security_group.api_service.id
  ip_protocol                  = "tcp"
  from_port                    = var.api_container_port
  to_port                      = var.api_container_port

  description = "API traffic from the ALB"
}

resource "aws_vpc_security_group_ingress_rule" "api_from_load_balancer" {
  security_group_id = aws_security_group.api_service.id

  referenced_security_group_id = aws_security_group.load_balancer.id
  ip_protocol                  = "tcp"
  from_port                    = var.api_container_port
  to_port                      = var.api_container_port

  description = "API traffic from the ALB"
}

resource "aws_lb" "this" {
  name = "${local.name}-alb"

  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.load_balancer.id]
  subnets                    = sort(tolist(var.public_subnet_ids))
  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_load_balancer_deletion_protection

  tags = local.common_tags
}

resource "aws_lb_target_group" "api" {
  name = "${local.name}-api"

  port        = var.api_container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  deregistration_delay = 30

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    path                = var.health_check_path
    port                = "traffic-port"
    protocol            = "HTTP"
    matcher             = "200-399"
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "http_forward" {
  count = var.certificate_arn == null ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count = var.certificate_arn == null ? 0 : 1

  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  count = var.certificate_arn == null ? 0 : 1

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"

  certificate_arn = var.certificate_arn
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}