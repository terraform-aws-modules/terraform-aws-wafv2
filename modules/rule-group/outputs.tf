################################################################################
# Rule Group Outputs
################################################################################

output "id" {
  description = "The ID of the WAF rule group"
  value       = try(aws_wafv2_rule_group.this[0].id, null)
}

output "arn" {
  description = "The ARN of the WAF rule group"
  value       = try(aws_wafv2_rule_group.this[0].arn, null)
}

output "lock_token" {
  description = "Lock token used by AWS to detect concurrent modifications"
  value       = try(aws_wafv2_rule_group.this[0].lock_token, null)
}

output "capacity" {
  description = "The capacity (WCUs) configured for the rule group"
  value       = try(aws_wafv2_rule_group.this[0].capacity, null)
}

output "tags_all" {
  description = "Map of tags assigned to the resource, including those inherited from the provider default_tags configuration block"
  value       = try(aws_wafv2_rule_group.this[0].tags_all, null)
}
