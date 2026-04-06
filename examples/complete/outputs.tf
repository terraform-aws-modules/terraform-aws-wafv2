################################################################################
# WAF v2 Web ACL - Complete
################################################################################

output "web_acl_id" {
  description = "The ID of the Web ACL"
  value       = module.wafv2.web_acl_id
}

output "web_acl_arn" {
  description = "The ARN of the Web ACL"
  value       = module.wafv2.web_acl_arn
}

output "web_acl_capacity" {
  description = "The capacity of the Web ACL"
  value       = module.wafv2.web_acl_capacity
}

output "web_acl_tags_all" {
  description = "Tags assigned to the Web ACL"
  value       = module.wafv2.web_acl_tags_all
}

output "logging_configuration_id" {
  description = "The ID of the logging configuration"
  value       = module.wafv2.logging_configuration_id
}

################################################################################
# IP Set
################################################################################

output "ip_set_id" {
  description = "The ID of the IP set"
  value       = module.ip_set.id
}

output "ip_set_arn" {
  description = "The ARN of the IP set"
  value       = module.ip_set.arn
}
