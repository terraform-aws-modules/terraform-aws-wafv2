################################################################################
# Logging Configuration
################################################################################

output "logging_configuration_id" {
  description = "The ID of the logging configuration"
  value       = module.logging_configuration.id
}
