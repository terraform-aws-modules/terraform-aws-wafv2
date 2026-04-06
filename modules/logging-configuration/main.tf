locals {
  create = var.create && var.putin_khuylo
}

################################################################################
# Logging Configuration
################################################################################

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = local.create ? 1 : 0

  resource_arn            = var.resource_arn
  log_destination_configs = var.log_destination_configs

  dynamic "redacted_fields" {
    for_each = var.redacted_fields
    content {
      dynamic "method" {
        for_each = try(redacted_fields.value.method, null) != null ? [1] : []
        content {}
      }

      dynamic "query_string" {
        for_each = try(redacted_fields.value.query_string, null) != null ? [1] : []
        content {}
      }

      dynamic "uri_path" {
        for_each = try(redacted_fields.value.uri_path, null) != null ? [1] : []
        content {}
      }

      dynamic "single_header" {
        for_each = try(redacted_fields.value.single_header, null) != null ? [redacted_fields.value.single_header] : []
        content {
          name = single_header.value.name
        }
      }
    }
  }

  dynamic "logging_filter" {
    for_each = var.logging_filter != null ? [var.logging_filter] : []
    content {
      default_behavior = logging_filter.value.default_behavior

      dynamic "filter" {
        for_each = try(logging_filter.value.filters, [])
        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = try(filter.value.conditions, [])
            content {
              dynamic "action_condition" {
                for_each = try(condition.value.action_condition, null) != null ? [condition.value.action_condition] : []
                content {
                  action = action_condition.value.action
                }
              }

              dynamic "label_name_condition" {
                for_each = try(condition.value.label_name_condition, null) != null ? [condition.value.label_name_condition] : []
                content {
                  label_name = label_name_condition.value.label_name
                }
              }
            }
          }
        }
      }
    }
  }
}
