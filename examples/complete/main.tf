provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "complete-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# WAF v2 Web ACL - Complete
################################################################################

module "wafv2" {
  source = "../.."

  name        = local.name
  description = "Complete WAF v2 Web ACL example"
  scope       = "REGIONAL"

  default_action = "allow"

  # Custom response bodies used by rules
  custom_response_bodies = {
    blocked_response = {
      content      = "{\"error\": \"Request blocked by WAF\"}"
      content_type = "APPLICATION_JSON"
    }
  }

  # CAPTCHA configuration
  captcha_config = {
    immunity_time_property = {
      immunity_time = 300
    }
  }

  rules = {
    # AWS Managed Rule Groups
    common-rule-set = {
      priority        = 1
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
      }
    }

    sqli-rule-set = {
      priority        = 2
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesSQLiRuleSet"
          vendor_name = "AWS"
        }
      }
    }

    known-bad-inputs = {
      priority        = 3
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
          vendor_name = "AWS"
        }
      }
    }

    # Managed rule group with scope_down_statement using regex_match_statement
    # Excludes specific URI paths from the admin protection rule set
    admin-protection-scoped = {
      priority        = 4
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesAdminProtectionRuleSet"
          vendor_name = "AWS"

          scope_down_statement = {
            regex_match_statement = {
              regex_string = "^/admin/.*"
              field_to_match = {
                uri_path = {}
              }
              text_transformations = [
                {
                  priority = 0
                  type     = "LOWERCASE"
                }
              ]
            }
          }
        }
      }
    }

    # Managed rule group with scope_down_statement using not_statement
    # Applies the common rule set only to requests NOT matching a specific path
    common-rules-scoped = {
      priority        = 5
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"

          scope_down_statement = {
            not_statement = {
              statement = {
                byte_match_statement = {
                  positional_constraint = "STARTS_WITH"
                  search_string         = "/api/health"
                  field_to_match = {
                    uri_path = {}
                  }
                  text_transformations = [
                    {
                      priority = 0
                      type     = "LOWERCASE"
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }

    # IP set reference rule
    block-bad-ips = {
      priority = 10
      action   = "block"

      statement = {
        ip_set_reference_statement = {
          arn = module.ip_set.arn
        }
      }
    }

    # Geo match rule - block specific countries
    geo-block = {
      priority = 20
      action = {
        block = {
          custom_response = {
            response_code            = 403
            custom_response_body_key = "blocked_response"
          }
        }
      }

      statement = {
        geo_match_statement = {
          country_codes = ["RU", "CN"]
        }
      }
    }

    # Rate-based rule
    rate-limit = {
      priority = 30
      action   = "block"

      statement = {
        rate_based_statement = {
          limit                 = 1000
          aggregate_key_type    = "IP"
          evaluation_window_sec = 300
        }
      }
    }

    # Byte match rule - block requests without specific header
    require-api-key = {
      priority = 40
      action   = "block"

      statement = {
        byte_match_statement = {
          positional_constraint = "EXACTLY"
          search_string         = "valid-api-key"
          field_to_match = {
            single_header = {
              name = "x-api-key"
            }
          }
          text_transformations = [
            {
              priority = 0
              type     = "NONE"
            }
          ]
        }
      }
    }

    # Size constraint rule
    limit-body-size = {
      priority = 50
      action   = "block"

      statement = {
        size_constraint_statement = {
          comparison_operator = "GT"
          size                = 8192
          field_to_match = {
            body = {
              oversize_handling = "MATCH"
            }
          }
          text_transformations = [
            {
              priority = 0
              type     = "NONE"
            }
          ]
        }
      }
    }
  }

  # Inline logging configuration
  create_logging_configuration    = true
  logging_log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  logging_redacted_fields = [
    {
      single_header = {
        name = "authorization"
      }
    }
  ]

  logging_filter = {
    default_behavior = "KEEP"
    filters = [
      {
        behavior    = "DROP"
        requirement = "MEETS_ALL"
        conditions = [
          {
            action_condition = {
              action = "ALLOW"
            }
          }
        ]
      }
    ]
  }

  tags = local.tags
}

################################################################################
# WAF v2 Web ACL - Disabled
################################################################################

module "disabled" {
  source = "../.."

  create = false

  name  = "disabled-${local.name}"
  scope = "REGIONAL"
}

################################################################################
# IP Set (Submodule)
################################################################################

module "ip_set" {
  source = "../../modules/ip-set"

  name               = "${local.name}-blocked-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = [
    "198.51.100.0/24",
    "203.0.113.0/24",
  ]

  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = 7

  tags = local.tags
}
