################################################################################
# Regex Pattern Set
################################################################################

output "id" {
  description = "The ID of the regex pattern set"
  value       = try(aws_wafv2_regex_pattern_set.this[0].id, null)
}

output "arn" {
  description = "The ARN of the regex pattern set"
  value       = try(aws_wafv2_regex_pattern_set.this[0].arn, null)
}

output "lock_token" {
  description = "A token used for optimistic locking"
  value       = try(aws_wafv2_regex_pattern_set.this[0].lock_token, null)
}

output "tags_all" {
  description = "A map of tags assigned to the resource, including those inherited from the provider default_tags configuration block"
  value       = try(aws_wafv2_regex_pattern_set.this[0].tags_all, {})
}
