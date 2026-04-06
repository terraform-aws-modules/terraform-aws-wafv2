locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# Regex Pattern Set
################################################################################

resource "aws_wafv2_regex_pattern_set" "this" {
  count = local.create ? 1 : 0

  name        = var.name
  description = var.description
  scope       = var.scope

  dynamic "regular_expression" {
    for_each = var.regular_expressions
    content {
      regex_string = regular_expression.value
    }
  }

  tags = var.tags
}
