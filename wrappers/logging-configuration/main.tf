module "wrapper" {
  source = "../../modules/logging-configuration"

  for_each = var.items

  create                  = try(each.value.create, var.defaults.create, true)
  log_destination_configs = try(each.value.log_destination_configs, var.defaults.log_destination_configs)
  logging_filter          = try(each.value.logging_filter, var.defaults.logging_filter, null)
  putin_khuylo            = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  redacted_fields         = try(each.value.redacted_fields, var.defaults.redacted_fields, [])
  resource_arn            = try(each.value.resource_arn, var.defaults.resource_arn)
}
