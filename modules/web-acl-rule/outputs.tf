################################################################################
# Web ACL Rule Outputs
################################################################################

output "name" {
  description = "Name of the rule"
  value       = try(aws_wafv2_web_acl_rule.this[0].name, null)
}

output "priority" {
  description = "Priority of the rule"
  value       = try(aws_wafv2_web_acl_rule.this[0].priority, null)
}

output "web_acl_arn" {
  description = "ARN of the Web ACL the rule is attached to"
  value       = try(aws_wafv2_web_acl_rule.this[0].web_acl_arn, null)
}
