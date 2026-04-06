################################################################################
# Regex Pattern Set
################################################################################

output "regex_pattern_set_id" {
  description = "The ID of the regex pattern set"
  value       = module.regex_pattern_set.id
}

output "regex_pattern_set_arn" {
  description = "The ARN of the regex pattern set"
  value       = module.regex_pattern_set.arn
}
