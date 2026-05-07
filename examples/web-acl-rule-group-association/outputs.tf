output "web_acl_arn" {
  description = "ARN of the Web ACL"
  value       = aws_wafv2_web_acl.this.arn
}

output "rule_group_arn" {
  description = "ARN of the custom Rule Group"
  value       = aws_wafv2_rule_group.this.arn
}
