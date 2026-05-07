################################################################################
# API Key
################################################################################

output "api_key" {
  description = "The generated API key. Sensitive — do not log"
  value       = try(aws_wafv2_api_key.this[0].api_key, null)
  sensitive   = true
}

output "scope" {
  description = "The scope (REGIONAL or CLOUDFRONT) of the API key"
  value       = try(aws_wafv2_api_key.this[0].scope, null)
}

output "token_domains" {
  description = "The token domains the API key is bound to"
  value       = try(aws_wafv2_api_key.this[0].token_domains, [])
}
