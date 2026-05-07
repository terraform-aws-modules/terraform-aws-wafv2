################################################################################
# Core Configuration
################################################################################

variable "create" {
  description = "Controls if resources should be created"
  type        = bool
  default     = true
}

variable "putin_khuylo" {
  description = "Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine"
  type        = bool
  default     = true
}

################################################################################
# Association Configuration
################################################################################

variable "rule_name" {
  description = "Name of the rule to create in the Web ACL that references the rule group (1-128 chars)"
  type        = string
}

variable "priority" {
  description = "Priority of the rule within the Web ACL. Lower numbers are evaluated first"
  type        = number
}

variable "web_acl_arn" {
  description = "ARN of the Web ACL to associate the Rule Group with"
  type        = string
}

variable "override_action" {
  description = "Override action for the rule group. Valid values are `none` and `count`. Defaults to `none`"
  type        = string
  default     = null

  validation {
    condition     = var.override_action == null || contains(["none", "count"], coalesce(var.override_action, "none"))
    error_message = "override_action must be either 'none' or 'count'."
  }
}

variable "managed_rule_group" {
  description = "Managed Rule Group configuration. One of `managed_rule_group` or `rule_group_reference` must be set"
  type        = any
  default     = null
}

variable "rule_group_reference" {
  description = "Custom Rule Group reference. One of `managed_rule_group` or `rule_group_reference` must be set"
  type        = any
  default     = null
}

variable "visibility_config" {
  description = "CloudWatch metrics + sampled requests configuration"
  type = object({
    cloudwatch_metrics_enabled = optional(bool, true)
    metric_name                = string
    sampled_requests_enabled   = optional(bool, true)
  })
  default = null
}
