module "wrapper" {
  source = "../../modules/api-key"

  for_each = var.items

  create        = try(each.value.create, var.defaults.create, true)
  putin_khuylo  = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  scope         = try(each.value.scope, var.defaults.scope, "REGIONAL")
  token_domains = try(each.value.token_domains, var.defaults.token_domains)
}
