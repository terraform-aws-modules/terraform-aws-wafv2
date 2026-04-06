################################################################################
# Web ACL Association
################################################################################

output "web_acl_association_id" {
  description = "The ID of the Web ACL association"
  value       = module.web_acl_association.id
}
