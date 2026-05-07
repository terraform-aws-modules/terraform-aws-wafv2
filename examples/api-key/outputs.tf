output "api_key" {
  description = "The generated API key (sensitive)"
  value       = module.api_key.api_key
  sensitive   = true
}

output "token_domains" {
  description = "The token domains the API key is bound to"
  value       = module.api_key.token_domains
}
