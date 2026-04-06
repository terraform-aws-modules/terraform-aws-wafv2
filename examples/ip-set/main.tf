provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "ip-set-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# IP Set
################################################################################

module "ip_set" {
  source = "../../modules/ip-set"

  name               = local.name
  description        = "Example IPv4 IP set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = [
    "198.51.100.0/24",
    "203.0.113.0/24",
  ]

  tags = local.tags
}

module "ip_set_ipv6" {
  source = "../../modules/ip-set"

  name               = "${local.name}-ipv6"
  description        = "Example IPv6 IP set"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"

  addresses = [
    "2001:db8::/32",
  ]

  tags = local.tags
}

################################################################################
# Disabled
################################################################################

module "disabled" {
  source = "../../modules/ip-set"

  create = false

  name = "disabled-${local.name}"
}
