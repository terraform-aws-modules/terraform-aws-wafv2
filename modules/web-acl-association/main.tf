locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# Web ACL Association
################################################################################

resource "aws_wafv2_web_acl_association" "this" {
  count = local.create ? 1 : 0

  web_acl_arn  = var.web_acl_arn
  resource_arn = var.resource_arn
}
