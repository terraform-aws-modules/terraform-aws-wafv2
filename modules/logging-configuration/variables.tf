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
# Logging Configuration
################################################################################

variable "resource_arn" {
  description = "The ARN of the Web ACL to associate with the logging configuration"
  type        = string
}

variable "log_destination_configs" {
  description = "The Amazon Kinesis Data Firehose, CloudWatch Log Group, or S3 Bucket Amazon Resource Names (ARNs) that you want to associate with the Web ACL"
  type        = list(string)
}

variable "redacted_fields" {
  description = "The parts of the request that you want to keep out of the logs. Each field identifies a single header, query string, method, or URI path"
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
