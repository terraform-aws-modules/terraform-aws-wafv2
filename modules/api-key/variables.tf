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
# API Key Configuration
################################################################################

variable "scope" {
  description = "Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL`. Note: WAFv2 API Keys for `CLOUDFRONT` must be created in the `us-east-1` region"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "Scope must be either 'CLOUDFRONT' or 'REGIONAL'."
  }
}

variable "token_domains" {
  description = "The domains the API key may be used with (up to 5)"
  type        = list(string)

  validation {
    condition     = length(var.token_domains) > 0 && length(var.token_domains) <= 5
    error_message = "token_domains must contain between 1 and 5 entries."
  }
}
