################################################################################
# Core Configuration
################################################################################

variable "create" {
  description = "Controls if resources should be created (affects all resources)"
  type        = bool
  default     = true
}

variable "putin_khuylo" {
  description = "Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine"
  type        = bool
  default     = true
}

variable "name" {
  description = "A friendly name of the Web ACL"
  type        = string
  default     = ""
}

variable "description" {
  description = "A friendly description of the Web ACL"
  type        = string
  default     = null
}

variable "scope" {
  description = "Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL`"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "Scope must be either 'CLOUDFRONT' or 'REGIONAL'."
  }
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

################################################################################
# Default Action Configuration
################################################################################

variable "default_action" {
  description = "Action to perform if none of the rules contained in the Web ACL match. Use `allow` or `block` for simple actions, or provide an object for custom request handling/response. See examples for object structure"
  type        = any
  default     = "allow"
}

################################################################################
# Visibility Configuration
################################################################################

variable "visibility_config" {
  description = "Visibility configuration for the Web ACL. Defines CloudWatch metrics configuration"
  type = object({
    cloudwatch_metrics_enabled = optional(bool, true)
    metric_name                = optional(string)
    sampled_requests_enabled   = optional(bool, true)
  })
  default = {}
}

################################################################################
# Rules Configuration
################################################################################

variable "rules" {
  description = <<-EOT
    Map of WAF rule configurations. The key is used as the rule name.

    Each rule supports:
    - `priority`          - (Required) Rule priority (lower = evaluated first)
    - `action`            - Action for standalone rules. Use string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom response
    - `override_action`   - Override action for managed/rule group rules. Use string (`none`, `count`) or object
    - `statement`         - (Required) Rule statement configuration. See AWS provider docs for statement structure
    - `visibility_config` - CloudWatch metrics config. Auto-generated from rule key if omitted
    - `captcha_config`    - Optional CAPTCHA configuration
    - `challenge_config`  - Optional challenge configuration
    - `rule_labels`       - Optional list of labels to add to matching requests

    See examples/complete for usage patterns.
  EOT
  type        = any
  default     = {}
}

variable "rule_json" {
  description = "Escape hatch: JSON string of WAF rules for cases where dynamic blocks cannot represent all provider features. Mutually exclusive with `rules`"
  type        = string
  default     = null
}

################################################################################
# Custom Response Bodies
################################################################################

variable "custom_response_bodies" {
  description = "Map of custom response body configurations. Key is the reference key, used in custom responses"
  type = map(object({
    content      = string
    content_type = string
  }))
  default = {}
}

################################################################################
# Token Domains
################################################################################

variable "token_domains" {
  description = "Specifies the domains that AWS WAF should accept in a web request token. Enables token use across multiple protected resources"
  type        = list(string)
  default     = []
}

################################################################################
# CAPTCHA Configuration
################################################################################

variable "captcha_config" {
  description = "CAPTCHA configuration for the Web ACL. Specifies how long a CAPTCHA timestamp is considered valid"
  type = object({
    immunity_time_property = object({
      immunity_time = number
    })
  })
  default = null
}

################################################################################
# Challenge Configuration
################################################################################

variable "challenge_config" {
  description = "Challenge configuration for the Web ACL. Specifies how long a challenge timestamp is considered valid"
  type = object({
    immunity_time_property = object({
      immunity_time = number
    })
  })
  default = null
}

################################################################################
# Association Configuration
################################################################################

variable "association_config" {
  description = "Configuration for body inspection size limits per resource type. Keys are resource types (e.g., `CLOUDFRONT`, `API_GATEWAY`, `COGNITO_USER_POOL`, `APP_RUNNER_SERVICE`, `VERIFIED_ACCESS_INSTANCE`)"
  type = map(object({
    default_size_inspection_limit = string
  }))
  default = {}
}

################################################################################
# Logging Configuration
################################################################################

variable "create_logging_configuration" {
  description = "Controls if a logging configuration should be created for the Web ACL"
  type        = bool
  default     = false
}

variable "logging_log_destination_configs" {
  description = "The Amazon Kinesis Data Firehose, CloudWatch Log Group, or S3 Bucket ARNs for the logging destination"
  type        = list(string)
  default     = []
}

variable "logging_redacted_fields" {
  description = "The parts of the request that you want to keep out of the logs"
  type        = any
  default     = []
}

variable "logging_filter" {
  description = "A configuration block that specifies which web requests are kept in the logs and which are dropped"
  type = object({
    default_behavior = string
    filters = list(object({
      behavior    = string
      requirement = string
      conditions = list(object({
        action_condition = optional(object({
          action = string
        }))
        label_name_condition = optional(object({
          label_name = string
        }))
      }))
    }))
  })
  default = null
}

################################################################################
# Web ACL Association
################################################################################

variable "association_resource_arns" {
  description = "Map of resource ARNs to associate with the Web ACL. Key is a friendly name, value is the resource ARN"
  type        = map(string)
  default     = {}
}
