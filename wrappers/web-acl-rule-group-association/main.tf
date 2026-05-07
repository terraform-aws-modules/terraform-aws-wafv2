module "wrapper" {
  source = "../../modules/web-acl-rule-group-association"

  for_each = var.items

  create               = try(each.value.create, var.defaults.create, true)
  managed_rule_group   = try(each.value.managed_rule_group, var.defaults.managed_rule_group, null)
  override_action      = try(each.value.override_action, var.defaults.override_action, null)
  priority             = try(each.value.priority, var.defaults.priority)
  putin_khuylo         = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  rule_group_reference = try(each.value.rule_group_reference, var.defaults.rule_group_reference, null)
  rule_name            = try(each.value.rule_name, var.defaults.rule_name)
  visibility_config    = try(each.value.visibility_config, var.defaults.visibility_config, null)
  web_acl_arn          = try(each.value.web_acl_arn, var.defaults.web_acl_arn)
}
