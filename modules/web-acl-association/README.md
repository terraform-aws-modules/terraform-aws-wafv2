# AWS WAF v2 Web ACL Association Submodule

Terraform submodule which creates an AWS WAF v2 Web ACL association.

## Usage

```hcl
module "web_acl_association" {
  source = "terraform-aws-modules/wafv2/aws//modules/web-acl-association"

  web_acl_arn  = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/12345678-1234-1234-1234-123456789012"
  resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.75 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.75 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_wafv2_web_acl_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created | `bool` | `true` | no |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_resource_arn"></a> [resource\_arn](#input\_resource\_arn) | The ARN of the resource to associate with the Web ACL (ALB, API Gateway, Cognito User Pool, AppSync, Verified Access) | `string` | n/a | yes |
| <a name="input_web_acl_arn"></a> [web\_acl\_arn](#input\_web\_acl\_arn) | The ARN of the Web ACL to associate with the resource | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_id"></a> [id](#output\_id) | The ID of the Web ACL association |
<!-- END_TF_DOCS -->
