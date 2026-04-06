module "wrapper" {
  source = "../"

  for_each = var.items

  association_config              = try(each.value.association_config, var.defaults.association_config, {})
  association_resource_arns       = try(each.value.association_resource_arns, var.defaults.association_resource_arns, {})
  captcha_config                  = try(each.value.captcha_config, var.defaults.captcha_config, null)
  challenge_config                = try(each.value.challenge_config, var.defaults.challenge_config, null)
  create                          = try(each.value.create, var.defaults.create, true)
  create_logging_configuration    = try(each.value.create_logging_configuration, var.defaults.create_logging_configuration, false)
  custom_response_bodies          = try(each.value.custom_response_bodies, var.defaults.custom_response_bodies, {})
  default_action                  = try(each.value.default_action, var.defaults.default_action, "allow")
  description                     = try(each.value.description, var.defaults.description, null)
  logging_filter                  = try(each.value.logging_filter, var.defaults.logging_filter, null)
  logging_log_destination_configs = try(each.value.logging_log_destination_configs, var.defaults.logging_log_destination_configs, [])
  logging_redacted_fields         = try(each.value.logging_redacted_fields, var.defaults.logging_redacted_fields, [])
  name                            = try(each.value.name, var.defaults.name, "")
  putin_khuylo                    = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  rule_json                       = try(each.value.rule_json, var.defaults.rule_json, null)
  rules                           = try(each.value.rules, var.defaults.rules, {})
  scope                           = try(each.value.scope, var.defaults.scope, "REGIONAL")
  tags                            = try(each.value.tags, var.defaults.tags, {})
  token_domains                   = try(each.value.token_domains, var.defaults.token_domains, [])
  visibility_config               = try(each.value.visibility_config, var.defaults.visibility_config, {})
}
