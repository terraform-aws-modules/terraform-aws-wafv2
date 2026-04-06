module "wrapper" {
  source = "../../modules/regex-pattern-set"

  for_each = var.items

  create              = try(each.value.create, var.defaults.create, true)
  description         = try(each.value.description, var.defaults.description, null)
  name                = try(each.value.name, var.defaults.name)
  putin_khuylo        = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  regular_expressions = try(each.value.regular_expressions, var.defaults.regular_expressions, [])
  scope               = try(each.value.scope, var.defaults.scope, "REGIONAL")
  tags                = try(each.value.tags, var.defaults.tags, {})
}
