module "wrapper" {
  source = "../../modules/web-acl-association"

  for_each = var.items

  create       = try(each.value.create, var.defaults.create, true)
  putin_khuylo = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  resource_arn = try(each.value.resource_arn, var.defaults.resource_arn)
  web_acl_arn  = try(each.value.web_acl_arn, var.defaults.web_acl_arn)
}
