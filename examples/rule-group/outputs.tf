output "rule_group_arn" {
  description = "ARN of the WAFv2 rule group created by this example"
  value       = module.rule_group.arn
}

output "rule_group_id" {
  description = "ID of the WAFv2 rule group"
  value       = module.rule_group.id
}

output "rule_group_capacity" {
  description = "Capacity (WCUs) configured for the rule group"
  value       = module.rule_group.capacity
}
