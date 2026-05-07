# AWS WAFv2 Web ACL Rule Group Association Example

Configuration in this directory creates a Web ACL, a custom Rule Group, then attaches both a managed rule group (AWS Common Rule Set) and the custom Rule Group to the Web ACL via the new `web-acl-rule-group-association` submodule.

## Usage

```bash
terraform init
terraform plan
terraform apply
terraform destroy
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.37 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.37 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_association_custom"></a> [association\_custom](#module\_association\_custom) | ../../modules/web-acl-rule-group-association | n/a |
| <a name="module_association_managed"></a> [association\_managed](#module\_association\_managed) | ../../modules/web-acl-rule-group-association | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_wafv2_rule_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_rule_group) | resource |
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_rule_group_arn"></a> [rule\_group\_arn](#output\_rule\_group\_arn) | ARN of the custom Rule Group |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the Web ACL |
<!-- END_TF_DOCS -->
