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

################################################################################
# Web ACL Rule Identity
################################################################################

variable "name" {
  description = "Name of the rule. Must be unique within the Web ACL"
  type        = string
}

variable "priority" {
  description = "Rule priority. Rules with lower priority are evaluated first"
  type        = number
}

variable "web_acl_arn" {
  description = "ARN of the Web ACL to add the rule to"
  type        = string
}

################################################################################
# Action / Override Action (mutually exclusive)
################################################################################

variable "action" {
  description = "Action to take when the rule matches. Use string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom request handling/response. Conflicts with `override_action`"
  type        = any
  default     = null
}

variable "override_action" {
  description = "Override action for managed rule groups and rule group reference statements. Use string (`none`, `count`) or object. Conflicts with `action`"
  type        = any
  default     = null
}

################################################################################
# Statement
################################################################################

variable "statement" {
  description = "Rule statement configuration. Required. Supports the full WAFv2 statement schema including managed_rule_group_statement, rate_based_statement, rule_group_reference_statement, and nested AND/OR/NOT logical statements"
  type        = any
}

################################################################################
# Visibility Configuration
################################################################################

variable "visibility_config" {
  description = "CloudWatch metrics configuration for this rule"
  type = object({
    cloudwatch_metrics_enabled = optional(bool, true)
    metric_name                = optional(string)
    sampled_requests_enabled   = optional(bool, true)
  })
}

################################################################################
# Rule Labels
################################################################################

variable "rule_label" {
  description = "List of labels to apply to matching web requests. Each entry must have a `name` field"
  type = list(object({
    name = string
  }))
  default = []
}

################################################################################
# CAPTCHA Configuration
################################################################################

variable "captcha_config" {
  description = "CAPTCHA configuration that overrides the Web ACL level setting"
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
  description = "Challenge configuration that overrides the Web ACL level setting"
  type = object({
    immunity_time_property = object({
      immunity_time = number
    })
  })
  default = null
}
