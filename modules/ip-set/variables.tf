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
# IP Set Configuration
################################################################################

variable "name" {
  description = "A friendly name of the IP set"
  type        = string
}

variable "description" {
  description = "A friendly description of the IP set"
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

variable "ip_address_version" {
  description = "Specify `IPV4` or `IPV6`. Valid values are `IPV4` or `IPV6`"
  type        = string
  default     = "IPV4"

  validation {
    condition     = contains(["IPV4", "IPV6"], var.ip_address_version)
    error_message = "IP address version must be either 'IPV4' or 'IPV6'."
  }
}

variable "addresses" {
  description = "Contains an array of strings that specifies zero or more IP addresses or blocks of IP addresses in CIDR notation"
  type        = list(string)
  default     = []
}
