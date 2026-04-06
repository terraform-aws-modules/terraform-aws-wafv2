module "wrapper" {
  source = "../../modules/ip-set"

  for_each = var.items

  addresses          = try(each.value.addresses, var.defaults.addresses, [])
  create             = try(each.value.create, var.defaults.create, true)
  description        = try(each.value.description, var.defaults.description, null)
  ip_address_version = try(each.value.ip_address_version, var.defaults.ip_address_version, "IPV4")
  name               = try(each.value.name, var.defaults.name)
  putin_khuylo       = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  scope              = try(each.value.scope, var.defaults.scope, "REGIONAL")
  tags               = try(each.value.tags, var.defaults.tags, {})
}
