module "wrapper" {
  source = "../../modules/rule-group"

  for_each = var.items

  capacity             = try(each.value.capacity, var.defaults.capacity)
  create               = try(each.value.create, var.defaults.create, true)
  custom_response_body = try(each.value.custom_response_body, var.defaults.custom_response_body, {})
  description          = try(each.value.description, var.defaults.description, null)
  name                 = try(each.value.name, var.defaults.name, "")
  name_prefix          = try(each.value.name_prefix, var.defaults.name_prefix, null)
  putin_khuylo         = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  rules                = try(each.value.rules, var.defaults.rules, {})
  scope                = try(each.value.scope, var.defaults.scope, "REGIONAL")
  tags                 = try(each.value.tags, var.defaults.tags, {})
  visibility_config    = try(each.value.visibility_config, var.defaults.visibility_config, {})
}
