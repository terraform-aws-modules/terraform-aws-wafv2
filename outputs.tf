################################################################################
# Web ACL
################################################################################

output "web_acl_id" {
  description = "The ID of the Web ACL"
  value       = try(aws_wafv2_web_acl.this[0].id, null)
}

output "web_acl_arn" {
  description = "The ARN of the Web ACL"
  value       = try(aws_wafv2_web_acl.this[0].arn, null)
}

output "web_acl_capacity" {
  description = "Web ACL capacity units (WCUs) currently being used by this Web ACL"
  value       = try(aws_wafv2_web_acl.this[0].capacity, null)
}

output "web_acl_name" {
  description = "The name of the Web ACL"
  value       = try(aws_wafv2_web_acl.this[0].name, null)
}

output "web_acl_description" {
  description = "The description of the Web ACL"
  value       = try(aws_wafv2_web_acl.this[0].description, null)
}

output "web_acl_lock_token" {
  description = "A token used for optimistic locking"
  value       = try(aws_wafv2_web_acl.this[0].lock_token, null)
}

output "web_acl_application_integration_url" {
  description = "The URL to use in SDK integrations with managed rule groups"
  value       = try(aws_wafv2_web_acl.this[0].application_integration_url, null)
}

output "web_acl_visibility_config" {
  description = "The visibility configuration of the Web ACL"
  value = try({
    cloudwatch_metrics_enabled = aws_wafv2_web_acl.this[0].visibility_config[0].cloudwatch_metrics_enabled
    metric_name                = aws_wafv2_web_acl.this[0].visibility_config[0].metric_name
    sampled_requests_enabled   = aws_wafv2_web_acl.this[0].visibility_config[0].sampled_requests_enabled
  }, null)
}

output "web_acl_rule_names" {
  description = "List of rule names in the Web ACL"
  value       = try([for rule in aws_wafv2_web_acl.this[0].rule : rule.name], [])
}

output "web_acl_tags_all" {
  description = "A map of tags assigned to the resource, including those inherited from the provider default_tags configuration block"
  value       = try(aws_wafv2_web_acl.this[0].tags_all, {})
}

################################################################################
# Web ACL Association
################################################################################

output "web_acl_association_ids" {
  description = "Map of Web ACL association IDs"
  value       = { for k, v in aws_wafv2_web_acl_association.this : k => v.id }
}

################################################################################
# Logging Configuration
################################################################################

output "logging_configuration_id" {
  description = "The ID of the WAF logging configuration"
  value       = try(aws_wafv2_web_acl_logging_configuration.this[0].id, null)
}
