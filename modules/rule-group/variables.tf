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
  description = "A friendly name of the rule group. Conflicts with `name_prefix`"
  type        = string
  default     = ""
}

variable "name_prefix" {
  description = "Creates a unique name beginning with the specified prefix. Conflicts with `name`"
  type        = string
  default     = null
}

variable "description" {
  description = "A friendly description of the rule group"
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

variable "capacity" {
  description = "The web ACL capacity units (WCUs) required for this rule group. Valid range is 1 to 1500"
  type        = number

  validation {
    condition     = var.capacity >= 1 && var.capacity <= 1500
    error_message = "Capacity must be between 1 and 1500."
  }
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

################################################################################
# Visibility Configuration
################################################################################

variable "visibility_config" {
  description = "Visibility configuration for the rule group. Defines CloudWatch metrics configuration"
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
    - `action`            - Action: string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom response
    - `statement`         - (Required) Rule statement configuration. See AWS provider docs for statement structure.
                            NOTE: rule groups cannot reference managed rule groups, rate-based statements,
                            or other rule groups, so those statement types are not supported here.
    - `visibility_config` - CloudWatch metrics config. Auto-generated from rule key if omitted
    - `captcha_config`    - Optional CAPTCHA configuration
    - `challenge_config`  - Optional challenge configuration
    - `rule_labels`       - Optional list of labels to add to matching requests
  EOT
  type        = any
  default     = {}
}

################################################################################
# Custom Response Bodies
################################################################################

variable "custom_response_body" {
  description = "Map of custom response body configurations. Key is the reference key, used in custom responses"
  type        = any
  default     = {}
}
