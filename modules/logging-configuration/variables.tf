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

variable "region" {
  description = "Region where the WAF logging configuration will be managed. Defaults to the provider region"
  type        = string
  default     = null
  nullable    = true
}

################################################################################
# Logging Configuration
################################################################################

variable "resource_arn" {
  description = "The ARN of the Web ACL to associate with the logging configuration"
  type        = string
}

variable "log_destination_configs" {
  description = "The Amazon Kinesis Data Firehose, CloudWatch Log Group, or S3 Bucket Amazon Resource Names (ARNs) that you want to associate with the Web ACL. Names must be prefixed with `aws-waf-logs-`"
  type        = list(string)

  validation {
    condition     = length(var.log_destination_configs) <= 8
    error_message = "AWS WAFv2 allows up to 8 log destinations per Web ACL."
  }

  validation {
    condition     = alltrue([for arn in var.log_destination_configs : strcontains(arn, "aws-waf-logs-")])
    error_message = "Each log destination ARN must reference a resource name prefixed with `aws-waf-logs-` (AWS API requirement)."
  }
}

variable "redacted_fields" {
  description = "The parts of the request that you want to keep out of the logs. Each entry must specify exactly one of `method`, `query_string`, `uri_path`, or `single_header`"
  type = list(object({
    method        = optional(object({}))
    query_string  = optional(object({}))
    uri_path      = optional(object({}))
    single_header = optional(object({ name = string }))
  }))
  default = []

  validation {
    condition     = length(var.redacted_fields) <= 100
    error_message = "AWS WAFv2 allows up to 100 redacted_fields blocks per logging configuration."
  }

  validation {
    condition = alltrue([
      for f in var.redacted_fields :
      length([for k, v in f : k if v != null]) == 1
    ])
    error_message = "Each redacted_fields entry must specify exactly one of `method`, `query_string`, `uri_path`, or `single_header`."
  }
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

  validation {
    condition     = var.logging_filter == null || contains(["KEEP", "DROP"], try(var.logging_filter.default_behavior, ""))
    error_message = "`logging_filter.default_behavior` must be `KEEP` or `DROP`."
  }

  validation {
    condition = var.logging_filter == null || alltrue([
      for f in try(var.logging_filter.filters, []) : contains(["KEEP", "DROP"], f.behavior)
    ])
    error_message = "Each `logging_filter.filters[*].behavior` must be `KEEP` or `DROP`."
  }

  validation {
    condition = var.logging_filter == null || alltrue([
      for f in try(var.logging_filter.filters, []) : contains(["MEETS_ALL", "MEETS_ANY"], f.requirement)
    ])
    error_message = "Each `logging_filter.filters[*].requirement` must be `MEETS_ALL` or `MEETS_ANY`."
  }

  validation {
    condition = var.logging_filter == null || alltrue([
      for f in try(var.logging_filter.filters, []) : length(f.conditions) >= 1
    ])
    error_message = "Each `logging_filter.filters[*]` must contain at least one condition."
  }

  validation {
    condition = var.logging_filter == null || alltrue(flatten([
      for f in try(var.logging_filter.filters, []) : [
        for c in f.conditions :
        length([for k, v in c : k if v != null]) == 1
      ]
    ]))
    error_message = "Each condition must specify exactly one of `action_condition` or `label_name_condition`."
  }

  validation {
    condition = var.logging_filter == null || alltrue(flatten([
      for f in try(var.logging_filter.filters, []) : [
        for c in f.conditions :
        contains(["ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE", "EXCLUDED_AS_COUNT", ""], try(c.action_condition.action, ""))
      ]
    ]))
    error_message = "`action_condition.action` must be one of ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE, EXCLUDED_AS_COUNT."
  }
}
