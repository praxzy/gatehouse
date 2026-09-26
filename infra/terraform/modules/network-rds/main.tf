locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(
    var.tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    },
  )

  public_subnets = {
    for index, availability_zone in var.availability_zones :
    availability_zone => {
      availability_zone = availability_zone
      cidr_block        = var.public_subnet_cidrs[index]
    }
  }

  application_subnets = {
    for index, availability_zone in var.availability_zones :
    availability_zone => {
      availability_zone = availability_zone
      cidr_block        = var.application_subnet_cidrs[index]
    }
  }

  database_subnets = {
    for index, availability_zone in var.availability_zones :
    availability_zone => {
      availability_zone = availability_zone
      cidr_block        = var.database_subnet_cidrs[index]
    }
  }

  nat_gateway_zones = (
    var.nat_gateway_mode == "none"
    ? toset([])
    : var.nat_gateway_mode == "single"
    ? toset([var.availability_zones[0]])
    : toset(var.availability_zones)
  )

  application_nat_routes = (
    var.nat_gateway_mode == "none"
    ? {}
    : {
      for availability_zone in var.availability_zones :
      availability_zone => (
        var.nat_gateway_mode == "single"
        ? var.availability_zones[0]
        : availability_zone
      )
    }
  )
}

check "matching_subnet_counts" {
  assert {
    condition = (
      length(var.public_subnet_cidrs) == length(var.availability_zones) &&
      length(var.application_subnet_cidrs) == length(var.availability_zones) &&
      length(var.database_subnet_cidrs) == length(var.availability_zones)
    )
    error_message = "Each subnet tier must provide exactly one CIDR block per availability zone."
  }
}

check "unique_subnet_cidrs" {
  assert {
    condition = length(distinct(concat(
      var.public_subnet_cidrs,
      var.application_subnet_cidrs,
      var.database_subnet_cidrs,
      ))) == length(concat(
      var.public_subnet_cidrs,
      var.application_subnet_cidrs,
      var.database_subnet_cidrs,
    ))
    error_message = "Every subnet must use a unique CIDR block."
  }
}

check "database_storage_range" {
  assert {
    condition = (
      var.database_max_allocated_storage >
      var.database_allocated_storage
    )
    error_message = "database_max_allocated_storage must be greater than database_allocated_storage."
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(
    local.common_tags,
    {
      Name = local.name_prefix
    },
  )
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-igw"
    },
  )
}

resource "aws_subnet" "public" {
  for_each = local.public_subnets

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-public-${each.key}"
      Tier = "public"
    },
  )
}

resource "aws_subnet" "application" {
  for_each = local.application_subnets

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-application-${each.key}"
      Tier = "application"
    },
  )
}

resource "aws_subnet" "database" {
  for_each = local.database_subnets

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-database-${each.key}"
      Tier = "database"
    },
  )
}