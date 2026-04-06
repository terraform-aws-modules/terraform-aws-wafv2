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

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

################################################################################
# Regex Pattern Set Configuration
################################################################################

variable "name" {
  description = "A friendly name of the regex pattern set"
  type        = string
}

variable "description" {
  description = "A friendly description of the regex pattern set"
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

variable "regular_expressions" {
  description = "Set of regex pattern strings"
  type        = set(string)
  default     = []
}
