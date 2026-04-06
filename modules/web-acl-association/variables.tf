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
# Web ACL Association Configuration
################################################################################

variable "web_acl_arn" {
  description = "The ARN of the Web ACL to associate with the resource"
  type        = string
}

variable "resource_arn" {
  description = "The ARN of the resource to associate with the Web ACL (ALB, API Gateway, Cognito User Pool, AppSync, Verified Access)"
  type        = string
}
