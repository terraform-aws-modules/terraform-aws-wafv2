locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# IP Set
################################################################################

resource "aws_wafv2_ip_set" "this" {
  count = local.create ? 1 : 0

  name               = var.name
  description        = var.description
  scope              = var.scope
  ip_address_version = var.ip_address_version
  addresses          = var.addresses

  tags = var.tags
}
