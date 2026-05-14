################################################################################
# Logging Configuration
################################################################################

output "logging_configuration_id" {
  description = "The ID of the logging configuration"
  value       = module.logging_configuration.id
}

output "logging_configuration_resource_arn" {
  description = "The ARN of the Web ACL associated with the logging configuration"
  value       = module.logging_configuration.resource_arn
}

################################################################################
# Supporting
################################################################################

output "web_acl_arn" {
  description = "The ARN of the Web ACL"
  value       = module.wafv2.web_acl_arn
}

output "cloudwatch_log_group_arn" {
  description = "The ARN of the CloudWatch log group used for WAF logs"
  value       = aws_cloudwatch_log_group.waf.arn
}
