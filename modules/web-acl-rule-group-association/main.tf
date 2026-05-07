locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# Web ACL Rule Group Association
################################################################################

resource "aws_wafv2_web_acl_rule_group_association" "this" {
  count = local.create ? 1 : 0

  rule_name       = var.rule_name
  priority        = var.priority
  web_acl_arn     = var.web_acl_arn
  override_action = var.override_action

  dynamic "managed_rule_group" {
    for_each = var.managed_rule_group != null ? [var.managed_rule_group] : []
    content {
      name        = managed_rule_group.value.name
      vendor_name = managed_rule_group.value.vendor_name
      version     = try(managed_rule_group.value.version, null)

      dynamic "managed_rule_group_configs" {
        for_each = try(managed_rule_group.value.managed_rule_group_configs, [])
        content {
          dynamic "aws_managed_rules_acfp_rule_set" {
            for_each = try(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set] : []
            content {
              creation_path          = aws_managed_rules_acfp_rule_set.value.creation_path
              registration_page_path = aws_managed_rules_acfp_rule_set.value.registration_page_path
              enable_regex_in_path   = try(aws_managed_rules_acfp_rule_set.value.enable_regex_in_path, null)
            }
          }

          dynamic "aws_managed_rules_atp_rule_set" {
            for_each = try(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_atp_rule_set] : []
            content {
              login_path           = aws_managed_rules_atp_rule_set.value.login_path
              enable_regex_in_path = try(aws_managed_rules_atp_rule_set.value.enable_regex_in_path, null)
            }
          }

          dynamic "aws_managed_rules_bot_control_rule_set" {
            for_each = try(managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set] : []
            content {
              inspection_level        = try(aws_managed_rules_bot_control_rule_set.value.inspection_level, null)
              enable_machine_learning = try(aws_managed_rules_bot_control_rule_set.value.enable_machine_learning, null)
            }
          }

          dynamic "aws_managed_rules_anti_ddos_rule_set" {
            for_each = try(managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set] : []
            content {
              sensitivity_to_block = try(aws_managed_rules_anti_ddos_rule_set.value.sensitivity_to_block, null)

              dynamic "client_side_action_config" {
                for_each = try(aws_managed_rules_anti_ddos_rule_set.value.client_side_action_config, null) != null ? [aws_managed_rules_anti_ddos_rule_set.value.client_side_action_config] : []
                content {
                  dynamic "challenge" {
                    for_each = try(client_side_action_config.value.challenge, null) != null ? [client_side_action_config.value.challenge] : []
                    content {
                      usage_of_action = challenge.value.usage_of_action
                      sensitivity     = try(challenge.value.sensitivity, null)

                      dynamic "exempt_uri_regular_expression" {
                        for_each = try(challenge.value.exempt_uri_regular_expression, [])
                        content {
                          regex_string = exempt_uri_regular_expression.value.regex_string
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "rule_action_override" {
        for_each = try(managed_rule_group.value.rule_action_overrides, {})
        content {
          name = rule_action_override.key
          action_to_use {
            dynamic "allow" {
              for_each = try(tostring(rule_action_override.value), null) == "allow" || try(rule_action_override.value.allow, null) != null ? [1] : []
              content {}
            }
            dynamic "block" {
              for_each = try(tostring(rule_action_override.value), null) == "block" || try(rule_action_override.value.block, null) != null ? [1] : []
              content {}
            }
            dynamic "count" {
              for_each = try(tostring(rule_action_override.value), null) == "count" || try(rule_action_override.value.count, null) != null ? [1] : []
              content {}
            }
            dynamic "captcha" {
              for_each = try(tostring(rule_action_override.value), null) == "captcha" || try(rule_action_override.value.captcha, null) != null ? [1] : []
              content {}
            }
            dynamic "challenge" {
              for_each = try(tostring(rule_action_override.value), null) == "challenge" || try(rule_action_override.value.challenge, null) != null ? [1] : []
              content {}
            }
          }
        }
      }
    }
  }

  dynamic "rule_group_reference" {
    for_each = var.rule_group_reference != null ? [var.rule_group_reference] : []
    content {
      arn = rule_group_reference.value.arn

      dynamic "rule_action_override" {
        for_each = try(rule_group_reference.value.rule_action_overrides, {})
        content {
          name = rule_action_override.key
          action_to_use {
            dynamic "allow" {
              for_each = try(tostring(rule_action_override.value), null) == "allow" || try(rule_action_override.value.allow, null) != null ? [1] : []
              content {}
            }
            dynamic "block" {
              for_each = try(tostring(rule_action_override.value), null) == "block" || try(rule_action_override.value.block, null) != null ? [1] : []
              content {}
            }
            dynamic "count" {
              for_each = try(tostring(rule_action_override.value), null) == "count" || try(rule_action_override.value.count, null) != null ? [1] : []
              content {}
            }
            dynamic "captcha" {
              for_each = try(tostring(rule_action_override.value), null) == "captcha" || try(rule_action_override.value.captcha, null) != null ? [1] : []
              content {}
            }
            dynamic "challenge" {
              for_each = try(tostring(rule_action_override.value), null) == "challenge" || try(rule_action_override.value.challenge, null) != null ? [1] : []
              content {}
            }
          }
        }
      }
    }
  }

  dynamic "visibility_config" {
    for_each = var.visibility_config != null ? [var.visibility_config] : []
    content {
      cloudwatch_metrics_enabled = visibility_config.value.cloudwatch_metrics_enabled
      metric_name                = visibility_config.value.metric_name
      sampled_requests_enabled   = visibility_config.value.sampled_requests_enabled
    }
  }
}
