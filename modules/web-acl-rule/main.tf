locals {
  create = var.create && var.putin_khuylo

  # Synthetic single-rule object: lets us reuse the rule body from the root
  # module's `dynamic "rule"` block by rewriting every `rule.value.X` reference
  # to `local.rule.X`.
  rule = {
    action            = var.action
    override_action   = var.override_action
    statement         = var.statement
    visibility_config = var.visibility_config
    rule_labels       = var.rule_label
    captcha_config    = var.captcha_config
    challenge_config  = var.challenge_config
  }
}

################################################################################
# Web ACL Rule (standalone, attached to existing Web ACL)
################################################################################

resource "aws_wafv2_web_acl_rule" "this" {
  count = local.create ? 1 : 0

  name        = var.name
  priority    = var.priority
  web_acl_arn = var.web_acl_arn


  # Action - supports string ("allow", "block", "count", "captcha", "challenge") or object
  dynamic "action" {
    for_each = try(local.rule.action, null) != null ? [local.rule.action] : []
    content {
      dynamic "allow" {
        for_each = try([action.value.allow], try(tostring(action.value), "") == "allow" ? [{}] : [])
        content {
          dynamic "custom_request_handling" {
            for_each = try(allow.value.custom_request_handling, null) != null ? [allow.value.custom_request_handling] : []
            content {
              dynamic "insert_header" {
                for_each = try(custom_request_handling.value.insert_headers, [])
                content {
                  name  = insert_header.value.name
                  value = insert_header.value.value
                }
              }
            }
          }
        }
      }

      dynamic "block" {
        for_each = try([action.value.block], try(tostring(action.value), "") == "block" ? [{}] : [])
        content {
          dynamic "custom_response" {
            for_each = try(block.value.custom_response, null) != null ? [block.value.custom_response] : []
            content {
              response_code            = custom_response.value.response_code
              custom_response_body_key = try(custom_response.value.custom_response_body_key, null)

              dynamic "response_header" {
                for_each = try(custom_response.value.response_headers, [])
                content {
                  name  = response_header.value.name
                  value = response_header.value.value
                }
              }
            }
          }
        }
      }

      dynamic "count" {
        for_each = try([action.value.count], try(tostring(action.value), "") == "count" ? [{}] : [])
        content {
          dynamic "custom_request_handling" {
            for_each = try(count.value.custom_request_handling, null) != null ? [count.value.custom_request_handling] : []
            content {
              dynamic "insert_header" {
                for_each = try(custom_request_handling.value.insert_headers, [])
                content {
                  name  = insert_header.value.name
                  value = insert_header.value.value
                }
              }
            }
          }
        }
      }

      dynamic "captcha" {
        for_each = try([action.value.captcha], try(tostring(action.value), "") == "captcha" ? [{}] : [])
        content {
          dynamic "custom_request_handling" {
            for_each = try(captcha.value.custom_request_handling, null) != null ? [captcha.value.custom_request_handling] : []
            content {
              dynamic "insert_header" {
                for_each = try(custom_request_handling.value.insert_headers, [])
                content {
                  name  = insert_header.value.name
                  value = insert_header.value.value
                }
              }
            }
          }
        }
      }

      dynamic "challenge" {
        for_each = try([action.value.challenge], try(tostring(action.value), "") == "challenge" ? [{}] : [])
        content {
          dynamic "custom_request_handling" {
            for_each = try(challenge.value.custom_request_handling, null) != null ? [challenge.value.custom_request_handling] : []
            content {
              dynamic "insert_header" {
                for_each = try(custom_request_handling.value.insert_headers, [])
                content {
                  name  = insert_header.value.name
                  value = insert_header.value.value
                }
              }
            }
          }
        }
      }
    }
  }

  # Override action - for managed rule groups and rule group reference statements
  dynamic "override_action" {
    for_each = try(local.rule.override_action, null) != null ? [local.rule.override_action] : []
    content {
      dynamic "none" {
        for_each = try(tostring(override_action.value), null) == "none" ? [1] : try(override_action.value.none, null) != null ? [1] : []
        content {}
      }

      dynamic "count" {
        for_each = try(tostring(override_action.value), null) == "count" ? [1] : try(override_action.value.count, null) != null ? [1] : []
        content {}
      }
    }
  }

  ########################################################################
  # Statement (Level 0)
  ########################################################################

  dynamic "statement" {
    for_each = [local.rule.statement]
    content {

      #-------------------------------------------------------------------
      # Byte Match Statement
      #-------------------------------------------------------------------
      dynamic "byte_match_statement" {
        for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
        content {
          positional_constraint = byte_match_statement.value.positional_constraint
          search_string         = byte_match_statement.value.search_string

          dynamic "field_to_match" {
            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content {
                  oversize_handling = try(body.value.oversize_handling, null)
                }
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content {
                  name = single_header.value.name
                }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content {
                  name = single_query_argument.value.name
                }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          dynamic "text_transformation" {
            for_each = byte_match_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Geo Match Statement
      #-------------------------------------------------------------------
      dynamic "geo_match_statement" {
        for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
        content {
          country_codes = geo_match_statement.value.country_codes

          dynamic "forwarded_ip_config" {
            for_each = try(geo_match_statement.value.forwarded_ip_config, null) != null ? [geo_match_statement.value.forwarded_ip_config] : []
            content {
              fallback_behavior = forwarded_ip_config.value.fallback_behavior
              header_name       = forwarded_ip_config.value.header_name
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # IP Set Reference Statement
      #-------------------------------------------------------------------
      dynamic "ip_set_reference_statement" {
        for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
        content {
          arn = ip_set_reference_statement.value.arn

          dynamic "ip_set_forwarded_ip_config" {
            for_each = try(ip_set_reference_statement.value.ip_set_forwarded_ip_config, null) != null ? [ip_set_reference_statement.value.ip_set_forwarded_ip_config] : []
            content {
              fallback_behavior = ip_set_forwarded_ip_config.value.fallback_behavior
              header_name       = ip_set_forwarded_ip_config.value.header_name
              position          = ip_set_forwarded_ip_config.value.position
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Label Match Statement
      #-------------------------------------------------------------------
      dynamic "label_match_statement" {
        for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
        content {
          key   = label_match_statement.value.key
          scope = label_match_statement.value.scope
        }
      }

      #-------------------------------------------------------------------
      # Managed Rule Group Statement
      #-------------------------------------------------------------------
      dynamic "managed_rule_group_statement" {
        for_each = try(statement.value.managed_rule_group_statement, null) != null ? [statement.value.managed_rule_group_statement] : []
        content {
          name        = managed_rule_group_statement.value.name
          vendor_name = managed_rule_group_statement.value.vendor_name
          version     = try(managed_rule_group_statement.value.version, null)

          dynamic "managed_rule_group_configs" {
            for_each = try(managed_rule_group_statement.value.managed_rule_group_configs, [])
            content {
              dynamic "aws_managed_rules_atp_rule_set" {
                for_each = try(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_atp_rule_set] : []
                content {
                  login_path = aws_managed_rules_atp_rule_set.value.login_path

                  dynamic "request_inspection" {
                    for_each = try(aws_managed_rules_atp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.request_inspection] : []
                    content {
                      payload_type = request_inspection.value.payload_type
                      dynamic "password_field" {
                        for_each = [request_inspection.value.password_field]
                        content {
                          identifier = password_field.value.identifier
                        }
                      }
                      dynamic "username_field" {
                        for_each = [request_inspection.value.username_field]
                        content {
                          identifier = username_field.value.identifier
                        }
                      }
                    }
                  }

                  dynamic "response_inspection" {
                    for_each = try(aws_managed_rules_atp_rule_set.value.response_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.response_inspection] : []
                    content {
                      dynamic "body_contains" {
                        for_each = try(response_inspection.value.body_contains, null) != null ? [response_inspection.value.body_contains] : []
                        content {
                          success_strings = body_contains.value.success_strings
                          failure_strings = body_contains.value.failure_strings
                        }
                      }
                      dynamic "header" {
                        for_each = try(response_inspection.value.header, null) != null ? [response_inspection.value.header] : []
                        content {
                          name           = header.value.name
                          success_values = header.value.success_values
                          failure_values = header.value.failure_values
                        }
                      }
                      dynamic "json" {
                        for_each = try(response_inspection.value.json, null) != null ? [response_inspection.value.json] : []
                        content {
                          identifier     = json.value.identifier
                          success_values = json.value.success_values
                          failure_values = json.value.failure_values
                        }
                      }
                      dynamic "status_code" {
                        for_each = try(response_inspection.value.status_code, null) != null ? [response_inspection.value.status_code] : []
                        content {
                          success_codes = status_code.value.success_codes
                          failure_codes = status_code.value.failure_codes
                        }
                      }
                    }
                  }
                }
              }

              dynamic "aws_managed_rules_bot_control_rule_set" {
                for_each = try(managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set] : []
                content {
                  inspection_level        = aws_managed_rules_bot_control_rule_set.value.inspection_level
                  enable_machine_learning = try(aws_managed_rules_bot_control_rule_set.value.enable_machine_learning, null)
                }
              }

              dynamic "aws_managed_rules_acfp_rule_set" {
                for_each = try(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set] : []
                content {
                  creation_path          = aws_managed_rules_acfp_rule_set.value.creation_path
                  registration_page_path = aws_managed_rules_acfp_rule_set.value.registration_page_path
                  enable_regex_in_path   = try(aws_managed_rules_acfp_rule_set.value.enable_regex_in_path, null)

                  dynamic "request_inspection" {
                    for_each = try(aws_managed_rules_acfp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_acfp_rule_set.value.request_inspection] : []
                    content {
                      payload_type = request_inspection.value.payload_type
                      dynamic "password_field" {
                        for_each = try(request_inspection.value.password_field, null) != null ? [request_inspection.value.password_field] : []
                        content {
                          identifier = password_field.value.identifier
                        }
                      }
                      dynamic "username_field" {
                        for_each = try(request_inspection.value.username_field, null) != null ? [request_inspection.value.username_field] : []
                        content {
                          identifier = username_field.value.identifier
                        }
                      }
                      dynamic "email_field" {
                        for_each = try(request_inspection.value.email_field, null) != null ? [request_inspection.value.email_field] : []
                        content {
                          identifier = email_field.value.identifier
                        }
                      }
                    }
                  }

                  dynamic "response_inspection" {
                    for_each = try(aws_managed_rules_acfp_rule_set.value.response_inspection, null) != null ? [aws_managed_rules_acfp_rule_set.value.response_inspection] : []
                    content {
                      dynamic "body_contains" {
                        for_each = try(response_inspection.value.body_contains, null) != null ? [response_inspection.value.body_contains] : []
                        content {
                          success_strings = body_contains.value.success_strings
                          failure_strings = body_contains.value.failure_strings
                        }
                      }
                      dynamic "header" {
                        for_each = try(response_inspection.value.header, null) != null ? [response_inspection.value.header] : []
                        content {
                          name           = header.value.name
                          success_values = header.value.success_values
                          failure_values = header.value.failure_values
                        }
                      }
                      dynamic "status_code" {
                        for_each = try(response_inspection.value.status_code, null) != null ? [response_inspection.value.status_code] : []
                        content {
                          success_codes = status_code.value.success_codes
                          failure_codes = status_code.value.failure_codes
                        }
                      }
                    }
                  }
                }
              }
            }
          }

          dynamic "rule_action_override" {
            for_each = try(managed_rule_group_statement.value.rule_action_overrides, {})
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

          dynamic "scope_down_statement" {
            for_each = try(managed_rule_group_statement.value.scope_down_statement, null) != null ? [managed_rule_group_statement.value.scope_down_statement] : []
            content {
              dynamic "byte_match_statement" {
                for_each = try(scope_down_statement.value.byte_match_statement, null) != null ? [scope_down_statement.value.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = byte_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "geo_match_statement" {
                for_each = try(scope_down_statement.value.geo_match_statement, null) != null ? [scope_down_statement.value.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }
              dynamic "ip_set_reference_statement" {
                for_each = try(scope_down_statement.value.ip_set_reference_statement, null) != null ? [scope_down_statement.value.ip_set_reference_statement] : []
                content {
                  arn = ip_set_reference_statement.value.arn
                }
              }
              dynamic "label_match_statement" {
                for_each = try(scope_down_statement.value.label_match_statement, null) != null ? [scope_down_statement.value.label_match_statement] : []
                content {
                  key   = label_match_statement.value.key
                  scope = label_match_statement.value.scope
                }
              }
              dynamic "regex_match_statement" {
                for_each = try(scope_down_statement.value.regex_match_statement, null) != null ? [scope_down_statement.value.regex_match_statement] : []
                content {
                  regex_string = regex_match_statement.value.regex_string

                  dynamic "field_to_match" {
                    for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = regex_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_pattern_set_reference_statement" {
                for_each = try(scope_down_statement.value.regex_pattern_set_reference_statement, null) != null ? [scope_down_statement.value.regex_pattern_set_reference_statement] : []
                content {
                  arn = regex_pattern_set_reference_statement.value.arn

                  dynamic "field_to_match" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = regex_pattern_set_reference_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "size_constraint_statement" {
                for_each = try(scope_down_statement.value.size_constraint_statement, null) != null ? [scope_down_statement.value.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size

                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = size_constraint_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "sqli_match_statement" {
                for_each = try(scope_down_statement.value.sqli_match_statement, null) != null ? [scope_down_statement.value.sqli_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)

                  dynamic "text_transformation" {
                    for_each = sqli_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "xss_match_statement" {
                for_each = try(scope_down_statement.value.xss_match_statement, null) != null ? [scope_down_statement.value.xss_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = xss_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Rate Based Statement
      #-------------------------------------------------------------------
      dynamic "rate_based_statement" {
        for_each = try(statement.value.rate_based_statement, null) != null ? [statement.value.rate_based_statement] : []
        content {
          aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
          evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, null)
          limit                 = rate_based_statement.value.limit

          dynamic "forwarded_ip_config" {
            for_each = try(rate_based_statement.value.forwarded_ip_config, null) != null ? [rate_based_statement.value.forwarded_ip_config] : []
            content {
              fallback_behavior = forwarded_ip_config.value.fallback_behavior
              header_name       = forwarded_ip_config.value.header_name
            }
          }

          dynamic "custom_keys" {
            for_each = try(rate_based_statement.value.custom_keys, [])
            content {
              dynamic "cookie" {
                for_each = try(custom_keys.value.cookie, null) != null ? [custom_keys.value.cookie] : []
                content {
                  name = cookie.value.name
                  dynamic "text_transformation" {
                    for_each = cookie.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "header" {
                for_each = try(custom_keys.value.header, null) != null ? [custom_keys.value.header] : []
                content {
                  name = header.value.name
                  dynamic "text_transformation" {
                    for_each = header.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "forwarded_ip" {
                for_each = try(custom_keys.value.forwarded_ip, null) != null ? [1] : []
                content {}
              }
              dynamic "ip" {
                for_each = try(custom_keys.value.ip, null) != null ? [1] : []
                content {}
              }
              dynamic "query_argument" {
                for_each = try(custom_keys.value.query_argument, null) != null ? [custom_keys.value.query_argument] : []
                content {
                  name = query_argument.value.name
                  dynamic "text_transformation" {
                    for_each = query_argument.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "query_string" {
                for_each = try(custom_keys.value.query_string, null) != null ? [custom_keys.value.query_string] : []
                content {
                  dynamic "text_transformation" {
                    for_each = query_string.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "uri_path" {
                for_each = try(custom_keys.value.uri_path, null) != null ? [custom_keys.value.uri_path] : []
                content {
                  dynamic "text_transformation" {
                    for_each = uri_path.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "label_namespace" {
                for_each = try(custom_keys.value.label_namespace, null) != null ? [custom_keys.value.label_namespace] : []
                content {
                  namespace = label_namespace.value.namespace
                }
              }
            }
          }

          dynamic "scope_down_statement" {
            for_each = try(rate_based_statement.value.scope_down_statement, null) != null ? [rate_based_statement.value.scope_down_statement] : []
            content {
              dynamic "byte_match_statement" {
                for_each = try(scope_down_statement.value.byte_match_statement, null) != null ? [scope_down_statement.value.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = byte_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "geo_match_statement" {
                for_each = try(scope_down_statement.value.geo_match_statement, null) != null ? [scope_down_statement.value.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }
              dynamic "ip_set_reference_statement" {
                for_each = try(scope_down_statement.value.ip_set_reference_statement, null) != null ? [scope_down_statement.value.ip_set_reference_statement] : []
                content {
                  arn = ip_set_reference_statement.value.arn
                }
              }
              dynamic "label_match_statement" {
                for_each = try(scope_down_statement.value.label_match_statement, null) != null ? [scope_down_statement.value.label_match_statement] : []
                content {
                  key   = label_match_statement.value.key
                  scope = label_match_statement.value.scope
                }
              }
              dynamic "regex_match_statement" {
                for_each = try(scope_down_statement.value.regex_match_statement, null) != null ? [scope_down_statement.value.regex_match_statement] : []
                content {
                  regex_string = regex_match_statement.value.regex_string

                  dynamic "field_to_match" {
                    for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = regex_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_pattern_set_reference_statement" {
                for_each = try(scope_down_statement.value.regex_pattern_set_reference_statement, null) != null ? [scope_down_statement.value.regex_pattern_set_reference_statement] : []
                content {
                  arn = regex_pattern_set_reference_statement.value.arn

                  dynamic "field_to_match" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = regex_pattern_set_reference_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "size_constraint_statement" {
                for_each = try(scope_down_statement.value.size_constraint_statement, null) != null ? [scope_down_statement.value.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size

                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = size_constraint_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "sqli_match_statement" {
                for_each = try(scope_down_statement.value.sqli_match_statement, null) != null ? [scope_down_statement.value.sqli_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)

                  dynamic "text_transformation" {
                    for_each = sqli_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "xss_match_statement" {
                for_each = try(scope_down_statement.value.xss_match_statement, null) != null ? [scope_down_statement.value.xss_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }

                  dynamic "text_transformation" {
                    for_each = xss_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Regex Match Statement
      #-------------------------------------------------------------------
      dynamic "regex_match_statement" {
        for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
        content {
          regex_string = regex_match_statement.value.regex_string

          dynamic "field_to_match" {
            for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content { oversize_handling = try(body.value.oversize_handling, null) }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content { name = single_header.value.name }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content { name = single_query_argument.value.name }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          dynamic "text_transformation" {
            for_each = regex_match_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Regex Pattern Set Reference Statement
      #-------------------------------------------------------------------
      dynamic "regex_pattern_set_reference_statement" {
        for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
        content {
          arn = regex_pattern_set_reference_statement.value.arn

          dynamic "field_to_match" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content { oversize_handling = try(body.value.oversize_handling, null) }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content { name = single_header.value.name }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content { name = single_query_argument.value.name }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          dynamic "text_transformation" {
            for_each = regex_pattern_set_reference_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # Rule Group Reference Statement
      #-------------------------------------------------------------------
      dynamic "rule_group_reference_statement" {
        for_each = try(statement.value.rule_group_reference_statement, null) != null ? [statement.value.rule_group_reference_statement] : []
        content {
          arn = rule_group_reference_statement.value.arn

          dynamic "rule_action_override" {
            for_each = try(rule_group_reference_statement.value.rule_action_overrides, {})
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

      #-------------------------------------------------------------------
      # Size Constraint Statement
      #-------------------------------------------------------------------
      dynamic "size_constraint_statement" {
        for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
        content {
          comparison_operator = size_constraint_statement.value.comparison_operator
          size                = size_constraint_statement.value.size

          dynamic "field_to_match" {
            for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content { oversize_handling = try(body.value.oversize_handling, null) }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content { name = single_header.value.name }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content { name = single_query_argument.value.name }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          dynamic "text_transformation" {
            for_each = size_constraint_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # SQLi Match Statement
      #-------------------------------------------------------------------
      dynamic "sqli_match_statement" {
        for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
        content {
          dynamic "field_to_match" {
            for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content { oversize_handling = try(body.value.oversize_handling, null) }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content { name = single_header.value.name }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content { name = single_query_argument.value.name }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)

          dynamic "text_transformation" {
            for_each = sqli_match_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # XSS Match Statement
      #-------------------------------------------------------------------
      dynamic "xss_match_statement" {
        for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
        content {
          dynamic "field_to_match" {
            for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
            content {
              dynamic "all_query_arguments" {
                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                content { oversize_handling = try(body.value.oversize_handling, null) }
              }
              dynamic "method" {
                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                content {}
              }
              dynamic "single_header" {
                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                content { name = single_header.value.name }
              }
              dynamic "single_query_argument" {
                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                content { name = single_query_argument.value.name }
              }
              dynamic "uri_path" {
                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                content {}
              }
              dynamic "cookies" {
                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                content {
                  match_scope       = cookies.value.match_scope
                  oversize_handling = cookies.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [cookies.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_cookies = try(match_pattern.value.included_cookies, null)
                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                    }
                  }
                }
              }
              dynamic "headers" {
                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                content {
                  match_scope       = headers.value.match_scope
                  oversize_handling = headers.value.oversize_handling
                  dynamic "match_pattern" {
                    for_each = [headers.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_headers = try(match_pattern.value.included_headers, null)
                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                    }
                  }
                }
              }
              dynamic "json_body" {
                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                content {
                  match_scope               = json_body.value.match_scope
                  oversize_handling         = try(json_body.value.oversize_handling, null)
                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                  dynamic "match_pattern" {
                    for_each = [json_body.value.match_pattern]
                    content {
                      dynamic "all" {
                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                        content {}
                      }
                      included_paths = try(match_pattern.value.included_paths, null)
                    }
                  }
                }
              }
              dynamic "header_order" {
                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                content {
                  oversize_handling = header_order.value.oversize_handling
                }
              }
              dynamic "ja3_fingerprint" {
                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                content {
                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                }
              }
            }
          }

          dynamic "text_transformation" {
            for_each = xss_match_statement.value.text_transformations
            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # NOT Statement (Level 0 -> Level 1)
      #-------------------------------------------------------------------
      dynamic "not_statement" {
        for_each = try(statement.value.not_statement, null) != null ? [statement.value.not_statement] : []
        content {
          dynamic "statement" {
            for_each = [not_statement.value.statement]
            content {
              dynamic "byte_match_statement" {
                for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = byte_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "geo_match_statement" {
                for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }
              dynamic "ip_set_reference_statement" {
                for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                content {
                  arn = ip_set_reference_statement.value.arn
                }
              }
              dynamic "label_match_statement" {
                for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                content {
                  key   = label_match_statement.value.key
                  scope = label_match_statement.value.scope
                }
              }
              dynamic "regex_match_statement" {
                for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                content {
                  regex_string = regex_match_statement.value.regex_string
                  dynamic "field_to_match" {
                    for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "size_constraint_statement" {
                for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size
                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = size_constraint_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "sqli_match_statement" {
                for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                  dynamic "text_transformation" {
                    for_each = sqli_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "xss_match_statement" {
                for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = xss_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_pattern_set_reference_statement" {
                for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                content {
                  arn = regex_pattern_set_reference_statement.value.arn
                  dynamic "field_to_match" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_pattern_set_reference_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # AND Statement (Level 0 -> Level 1)
      #-------------------------------------------------------------------
      dynamic "and_statement" {
        for_each = try(statement.value.and_statement, null) != null ? [statement.value.and_statement] : []
        content {
          dynamic "statement" {
            for_each = try(and_statement.value.statements, [])
            content {
              dynamic "byte_match_statement" {
                for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = byte_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "geo_match_statement" {
                for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }
              dynamic "ip_set_reference_statement" {
                for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                content {
                  arn = ip_set_reference_statement.value.arn
                }
              }
              dynamic "label_match_statement" {
                for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                content {
                  key   = label_match_statement.value.key
                  scope = label_match_statement.value.scope
                }
              }
              dynamic "size_constraint_statement" {
                for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size
                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = size_constraint_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "sqli_match_statement" {
                for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                  dynamic "text_transformation" {
                    for_each = sqli_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "xss_match_statement" {
                for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = xss_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_match_statement" {
                for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                content {
                  regex_string = regex_match_statement.value.regex_string
                  dynamic "field_to_match" {
                    for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_pattern_set_reference_statement" {
                for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                content {
                  arn = regex_pattern_set_reference_statement.value.arn
                  dynamic "field_to_match" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_pattern_set_reference_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              # Nested NOT inside AND (Level 2)
              dynamic "not_statement" {
                for_each = try(statement.value.not_statement, null) != null ? [statement.value.not_statement] : []
                content {
                  dynamic "statement" {
                    for_each = [not_statement.value.statement]
                    content {
                      dynamic "geo_match_statement" {
                        for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                        content { country_codes = geo_match_statement.value.country_codes }
                      }
                      dynamic "ip_set_reference_statement" {
                        for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                        content { arn = ip_set_reference_statement.value.arn }
                      }
                      dynamic "label_match_statement" {
                        for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                        content {
                          key   = label_match_statement.value.key
                          scope = label_match_statement.value.scope
                        }
                      }
                      dynamic "byte_match_statement" {
                        for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = byte_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_match_statement" {
                        for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                        content {
                          regex_string = regex_match_statement.value.regex_string

                          dynamic "field_to_match" {
                            for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }

                          dynamic "text_transformation" {
                            for_each = regex_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "size_constraint_statement" {
                        for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                        content {
                          comparison_operator = size_constraint_statement.value.comparison_operator
                          size                = size_constraint_statement.value.size
                          dynamic "field_to_match" {
                            for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = size_constraint_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "sqli_match_statement" {
                        for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                          dynamic "text_transformation" {
                            for_each = sqli_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "xss_match_statement" {
                        for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = xss_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_pattern_set_reference_statement" {
                        for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                        content {
                          arn = regex_pattern_set_reference_statement.value.arn
                          dynamic "field_to_match" {
                            for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = regex_pattern_set_reference_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      # Nested NOT inside AND (Level 2)
                    }
                  }
                }
              }
              # Nested OR inside AND (Level 2)
              dynamic "or_statement" {
                for_each = try(statement.value.or_statement, null) != null ? [statement.value.or_statement] : []
                content {
                  dynamic "statement" {
                    for_each = try(or_statement.value.statements, [])
                    content {
                      dynamic "geo_match_statement" {
                        for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                        content { country_codes = geo_match_statement.value.country_codes }
                      }
                      dynamic "ip_set_reference_statement" {
                        for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                        content { arn = ip_set_reference_statement.value.arn }
                      }
                      dynamic "label_match_statement" {
                        for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                        content {
                          key   = label_match_statement.value.key
                          scope = label_match_statement.value.scope
                        }
                      }
                      dynamic "byte_match_statement" {
                        for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = byte_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_match_statement" {
                        for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                        content {
                          regex_string = regex_match_statement.value.regex_string

                          dynamic "field_to_match" {
                            for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }

                          dynamic "text_transformation" {
                            for_each = regex_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "size_constraint_statement" {
                        for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                        content {
                          comparison_operator = size_constraint_statement.value.comparison_operator
                          size                = size_constraint_statement.value.size
                          dynamic "field_to_match" {
                            for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = size_constraint_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "sqli_match_statement" {
                        for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                          dynamic "text_transformation" {
                            for_each = sqli_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "xss_match_statement" {
                        for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = xss_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_pattern_set_reference_statement" {
                        for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                        content {
                          arn = regex_pattern_set_reference_statement.value.arn
                          dynamic "field_to_match" {
                            for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = regex_pattern_set_reference_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      # Nested NOT inside AND (Level 2)
                    }
                  }
                }
              }
            }
          }
        }
      }

      #-------------------------------------------------------------------
      # OR Statement (Level 0 -> Level 1)
      # Same structure as AND statement
      #-------------------------------------------------------------------
      dynamic "or_statement" {
        for_each = try(statement.value.or_statement, null) != null ? [statement.value.or_statement] : []
        content {
          dynamic "statement" {
            for_each = try(or_statement.value.statements, [])
            content {
              dynamic "byte_match_statement" {
                for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "single_query_argument" {
                        for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                        content { name = single_query_argument.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = byte_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "geo_match_statement" {
                for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }
              dynamic "ip_set_reference_statement" {
                for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                content {
                  arn = ip_set_reference_statement.value.arn
                }
              }
              dynamic "label_match_statement" {
                for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                content {
                  key   = label_match_statement.value.key
                  scope = label_match_statement.value.scope
                }
              }
              dynamic "size_constraint_statement" {
                for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size
                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = size_constraint_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "sqli_match_statement" {
                for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                  dynamic "text_transformation" {
                    for_each = sqli_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "xss_match_statement" {
                for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                content {
                  dynamic "field_to_match" {
                    for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = xss_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_match_statement" {
                for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                content {
                  regex_string = regex_match_statement.value.regex_string
                  dynamic "field_to_match" {
                    for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_match_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              dynamic "regex_pattern_set_reference_statement" {
                for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                content {
                  arn = regex_pattern_set_reference_statement.value.arn
                  dynamic "field_to_match" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                    content {
                      dynamic "all_query_arguments" {
                        for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                        content { oversize_handling = try(body.value.oversize_handling, null) }
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content { name = single_header.value.name }
                      }
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "cookies" {
                        for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                        content {
                          match_scope       = cookies.value.match_scope
                          oversize_handling = cookies.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [cookies.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_cookies = try(match_pattern.value.included_cookies, null)
                              excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                            }
                          }
                        }
                      }
                      dynamic "headers" {
                        for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                        content {
                          match_scope       = headers.value.match_scope
                          oversize_handling = headers.value.oversize_handling
                          dynamic "match_pattern" {
                            for_each = [headers.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_headers = try(match_pattern.value.included_headers, null)
                              excluded_headers = try(match_pattern.value.excluded_headers, null)
                            }
                          }
                        }
                      }
                      dynamic "json_body" {
                        for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                        content {
                          match_scope               = json_body.value.match_scope
                          oversize_handling         = try(json_body.value.oversize_handling, null)
                          invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                          dynamic "match_pattern" {
                            for_each = [json_body.value.match_pattern]
                            content {
                              dynamic "all" {
                                for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                content {}
                              }
                              included_paths = try(match_pattern.value.included_paths, null)
                            }
                          }
                        }
                      }
                      dynamic "header_order" {
                        for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                        content {
                          oversize_handling = header_order.value.oversize_handling
                        }
                      }
                      dynamic "ja3_fingerprint" {
                        for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                        content {
                          fallback_behavior = ja3_fingerprint.value.fallback_behavior
                        }
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = regex_pattern_set_reference_statement.value.text_transformations
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }
              # Nested NOT inside OR (Level 2)
              dynamic "not_statement" {
                for_each = try(statement.value.not_statement, null) != null ? [statement.value.not_statement] : []
                content {
                  dynamic "statement" {
                    for_each = [not_statement.value.statement]
                    content {
                      dynamic "geo_match_statement" {
                        for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                        content { country_codes = geo_match_statement.value.country_codes }
                      }
                      dynamic "ip_set_reference_statement" {
                        for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                        content { arn = ip_set_reference_statement.value.arn }
                      }
                      dynamic "label_match_statement" {
                        for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                        content {
                          key   = label_match_statement.value.key
                          scope = label_match_statement.value.scope
                        }
                      }
                      dynamic "byte_match_statement" {
                        for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = byte_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_match_statement" {
                        for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                        content {
                          regex_string = regex_match_statement.value.regex_string

                          dynamic "field_to_match" {
                            for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }

                          dynamic "text_transformation" {
                            for_each = regex_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "size_constraint_statement" {
                        for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                        content {
                          comparison_operator = size_constraint_statement.value.comparison_operator
                          size                = size_constraint_statement.value.size
                          dynamic "field_to_match" {
                            for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = size_constraint_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "sqli_match_statement" {
                        for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                          dynamic "text_transformation" {
                            for_each = sqli_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "xss_match_statement" {
                        for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = xss_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_pattern_set_reference_statement" {
                        for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                        content {
                          arn = regex_pattern_set_reference_statement.value.arn
                          dynamic "field_to_match" {
                            for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = regex_pattern_set_reference_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      # Nested NOT inside AND (Level 2)
                    }
                  }
                }
              }
              # Nested AND inside OR (Level 2)
              dynamic "and_statement" {
                for_each = try(statement.value.and_statement, null) != null ? [statement.value.and_statement] : []
                content {
                  dynamic "statement" {
                    for_each = try(and_statement.value.statements, [])
                    content {
                      dynamic "geo_match_statement" {
                        for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                        content { country_codes = geo_match_statement.value.country_codes }
                      }
                      dynamic "ip_set_reference_statement" {
                        for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                        content { arn = ip_set_reference_statement.value.arn }
                      }
                      dynamic "label_match_statement" {
                        for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                        content {
                          key   = label_match_statement.value.key
                          scope = label_match_statement.value.scope
                        }
                      }
                      dynamic "byte_match_statement" {
                        for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = byte_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_match_statement" {
                        for_each = try(statement.value.regex_match_statement, null) != null ? [statement.value.regex_match_statement] : []
                        content {
                          regex_string = regex_match_statement.value.regex_string

                          dynamic "field_to_match" {
                            for_each = try(regex_match_statement.value.field_to_match, null) != null ? [regex_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "single_query_argument" {
                                for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                                content { name = single_query_argument.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }

                          dynamic "text_transformation" {
                            for_each = regex_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "size_constraint_statement" {
                        for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                        content {
                          comparison_operator = size_constraint_statement.value.comparison_operator
                          size                = size_constraint_statement.value.size
                          dynamic "field_to_match" {
                            for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = size_constraint_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "sqli_match_statement" {
                        for_each = try(statement.value.sqli_match_statement, null) != null ? [statement.value.sqli_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(sqli_match_statement.value.field_to_match, null) != null ? [sqli_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
                          dynamic "text_transformation" {
                            for_each = sqli_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "xss_match_statement" {
                        for_each = try(statement.value.xss_match_statement, null) != null ? [statement.value.xss_match_statement] : []
                        content {
                          dynamic "field_to_match" {
                            for_each = try(xss_match_statement.value.field_to_match, null) != null ? [xss_match_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = xss_match_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      dynamic "regex_pattern_set_reference_statement" {
                        for_each = try(statement.value.regex_pattern_set_reference_statement, null) != null ? [statement.value.regex_pattern_set_reference_statement] : []
                        content {
                          arn = regex_pattern_set_reference_statement.value.arn
                          dynamic "field_to_match" {
                            for_each = try(regex_pattern_set_reference_statement.value.field_to_match, null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
                            content {
                              dynamic "all_query_arguments" {
                                for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "body" {
                                for_each = try(field_to_match.value.body, null) != null ? [field_to_match.value.body] : []
                                content { oversize_handling = try(body.value.oversize_handling, null) }
                              }
                              dynamic "method" {
                                for_each = try(field_to_match.value.method, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content { name = single_header.value.name }
                              }
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "cookies" {
                                for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                                content {
                                  match_scope       = cookies.value.match_scope
                                  oversize_handling = cookies.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [cookies.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_cookies = try(match_pattern.value.included_cookies, null)
                                      excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                                    }
                                  }
                                }
                              }
                              dynamic "headers" {
                                for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                                content {
                                  match_scope       = headers.value.match_scope
                                  oversize_handling = headers.value.oversize_handling
                                  dynamic "match_pattern" {
                                    for_each = [headers.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_headers = try(match_pattern.value.included_headers, null)
                                      excluded_headers = try(match_pattern.value.excluded_headers, null)
                                    }
                                  }
                                }
                              }
                              dynamic "json_body" {
                                for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                                content {
                                  match_scope               = json_body.value.match_scope
                                  oversize_handling         = try(json_body.value.oversize_handling, null)
                                  invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                                  dynamic "match_pattern" {
                                    for_each = [json_body.value.match_pattern]
                                    content {
                                      dynamic "all" {
                                        for_each = try(match_pattern.value.all, null) != null ? [1] : []
                                        content {}
                                      }
                                      included_paths = try(match_pattern.value.included_paths, null)
                                    }
                                  }
                                }
                              }
                              dynamic "header_order" {
                                for_each = try(field_to_match.value.header_order, null) != null ? [field_to_match.value.header_order] : []
                                content {
                                  oversize_handling = header_order.value.oversize_handling
                                }
                              }
                              dynamic "ja3_fingerprint" {
                                for_each = try(field_to_match.value.ja3_fingerprint, null) != null ? [field_to_match.value.ja3_fingerprint] : []
                                content {
                                  fallback_behavior = ja3_fingerprint.value.fallback_behavior
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = regex_pattern_set_reference_statement.value.text_transformations
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }
                      # Nested NOT inside AND (Level 2)
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

  ########################################################################
  # Per-Rule Visibility Config
  ########################################################################

  visibility_config {
    cloudwatch_metrics_enabled = try(local.rule.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = coalesce(try(local.rule.visibility_config.metric_name, null), var.name)
    sampled_requests_enabled   = try(local.rule.visibility_config.sampled_requests_enabled, true)
  }

  # Per-rule CAPTCHA config
  dynamic "captcha_config" {
    for_each = try(local.rule.captcha_config, null) != null ? [local.rule.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time_property.immunity_time
      }
    }
  }

  # Per-rule challenge config
  dynamic "challenge_config" {
    for_each = try(local.rule.challenge_config, null) != null ? [local.rule.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time_property.immunity_time
      }
    }
  }

  # Per-rule labels
  dynamic "rule_label" {
    for_each = try(local.rule.rule_labels, [])
    content {
      name = rule_label.value.name
    }
  }

  lifecycle {
    precondition {
      condition     = (var.action == null) != (var.override_action == null)
      error_message = "Exactly one of `action` or `override_action` must be set."
    }
  }
}
