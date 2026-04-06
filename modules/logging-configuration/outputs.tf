################################################################################
# Logging Configuration
################################################################################

output "id" {
  description = "The ID of the WAF logging configuration"
  value       = try(aws_wafv2_web_acl_logging_configuration.this[0].id, null)
}
