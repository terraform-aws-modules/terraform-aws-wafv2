################################################################################
# WAF v2 Web ACL
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
