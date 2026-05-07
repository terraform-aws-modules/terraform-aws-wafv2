output "rule_name" {
  description = "Name of the rule created in the Web ACL"
  value       = try(aws_wafv2_web_acl_rule_group_association.this[0].rule_name, null)
}

output "priority" {
  description = "Priority of the rule"
  value       = try(aws_wafv2_web_acl_rule_group_association.this[0].priority, null)
}

output "web_acl_arn" {
  description = "ARN of the parent Web ACL"
  value       = try(aws_wafv2_web_acl_rule_group_association.this[0].web_acl_arn, null)
}
