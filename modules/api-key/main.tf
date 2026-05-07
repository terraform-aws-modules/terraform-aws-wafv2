locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# API Key
################################################################################

resource "aws_wafv2_api_key" "this" {
  count = local.create ? 1 : 0

  scope         = var.scope
  token_domains = var.token_domains
}
