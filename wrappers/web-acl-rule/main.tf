module "wrapper" {
  source = "../../modules/web-acl-rule"

  for_each = var.items

  action            = try(each.value.action, var.defaults.action, null)
  captcha_config    = try(each.value.captcha_config, var.defaults.captcha_config, null)
  challenge_config  = try(each.value.challenge_config, var.defaults.challenge_config, null)
  create            = try(each.value.create, var.defaults.create, true)
  name              = try(each.value.name, var.defaults.name)
  override_action   = try(each.value.override_action, var.defaults.override_action, null)
  priority          = try(each.value.priority, var.defaults.priority)
  putin_khuylo      = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  rule_label        = try(each.value.rule_label, var.defaults.rule_label, [])
  statement         = try(each.value.statement, var.defaults.statement)
  visibility_config = try(each.value.visibility_config, var.defaults.visibility_config)
  web_acl_arn       = try(each.value.web_acl_arn, var.defaults.web_acl_arn)
}
