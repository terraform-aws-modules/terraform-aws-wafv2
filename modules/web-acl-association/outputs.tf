################################################################################
# Web ACL Association
################################################################################

output "id" {
  description = "The ID of the Web ACL association"
  value       = try(aws_wafv2_web_acl_association.this[0].id, null)
}
