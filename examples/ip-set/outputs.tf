################################################################################
# IP Set
################################################################################

output "ip_set_id" {
  description = "The ID of the IP set"
  value       = module.ip_set.id
}

output "ip_set_arn" {
  description = "The ARN of the IP set"
  value       = module.ip_set.arn
}

################################################################################
# IP Set IPv6
################################################################################

output "ip_set_ipv6_id" {
  description = "The ID of the IPv6 IP set"
  value       = module.ip_set_ipv6.id
}

output "ip_set_ipv6_arn" {
  description = "The ARN of the IPv6 IP set"
  value       = module.ip_set_ipv6.arn
}
