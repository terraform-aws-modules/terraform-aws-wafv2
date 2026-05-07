locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# Rule Group
################################################################################

resource "aws_wafv2_rule_group" "this" {
  count = local.create ? 1 : 0

  name        = var.name == "" ? null : var.name
  name_prefix = var.name_prefix
  description = var.description
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = var.visibility_config.cloudwatch_metrics_enabled
    metric_name                = coalesce(var.visibility_config.metric_name, var.name != "" ? var.name : null, var.name_prefix)
    sampled_requests_enabled   = var.visibility_config.sampled_requests_enabled
  }

  # Custom response bodies
  dynamic "custom_response_body" {
    for_each = var.custom_response_body
    content {
      key          = custom_response_body.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }

  dynamic "rule" {
    for_each = var.rules
    content {
      name     = rule.key
      priority = rule.value.priority

      # Action - supports string ("allow", "block", "count", "captcha", "challenge") or object
      dynamic "action" {
        for_each = try(rule.value.action, null) != null ? [rule.value.action] : []
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
      ########################################################################
      # Statement (Level 0)
      ########################################################################

      dynamic "statement" {
        for_each = [rule.value.statement]
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
        cloudwatch_metrics_enabled = try(rule.value.visibility_config.cloudwatch_metrics_enabled, true)
        metric_name                = try(rule.value.visibility_config.metric_name, rule.key)
        sampled_requests_enabled   = try(rule.value.visibility_config.sampled_requests_enabled, true)
      }

      # Per-rule CAPTCHA config
      dynamic "captcha_config" {
        for_each = try(rule.value.captcha_config, null) != null ? [rule.value.captcha_config] : []
        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }
      # Per-rule labels
      dynamic "rule_label" {
        for_each = try(rule.value.rule_labels, [])
        content {
          name = rule_label.value.name
        }
      }
    }
  }

  tags = var.tags
}
