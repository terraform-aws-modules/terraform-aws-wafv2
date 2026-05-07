output "web_acl_arn" {
  description = "ARN of the Web ACL the standalone rules are attached to"
  value       = aws_wafv2_web_acl.this.arn
}

output "block_high_risk_geos_name" {
  description = "Name of the geo-match standalone rule"
  value       = module.block_high_risk_geos.name
}

output "rate_limit_per_ip_name" {
  description = "Name of the rate-based standalone rule"
  value       = module.rate_limit_per_ip.name
}
