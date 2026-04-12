# Complete Example

Configuration in this directory creates an AWS WAF v2 Web ACL with most features enabled, including multiple rule types, custom responses, logging, and associations.

## Usage

To run this example you need to execute:

```bash
$ terraform init
$ terraform plan
$ terraform apply
```

Note that this example may create resources which cost money. Run `terraform destroy` when you don't need these resources.

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

| Name | Source | Version |
|------|--------|---------|
| <a name="module_disabled"></a> [disabled](#module\_disabled) | ../.. | n/a |
| <a name="module_ip_set"></a> [ip\_set](#module\_ip\_set) | ../../modules/ip-set | n/a |
| <a name="module_wafv2"></a> [wafv2](#module\_wafv2) | ../.. | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.waf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ip_set_arn"></a> [ip\_set\_arn](#output\_ip\_set\_arn) | The ARN of the IP set |
| <a name="output_ip_set_id"></a> [ip\_set\_id](#output\_ip\_set\_id) | The ID of the IP set |
| <a name="output_logging_configuration_id"></a> [logging\_configuration\_id](#output\_logging\_configuration\_id) | The ID of the logging configuration |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | The ARN of the Web ACL |
| <a name="output_web_acl_capacity"></a> [web\_acl\_capacity](#output\_web\_acl\_capacity) | The capacity of the Web ACL |
| <a name="output_web_acl_id"></a> [web\_acl\_id](#output\_web\_acl\_id) | The ID of the Web ACL |
| <a name="output_web_acl_tags_all"></a> [web\_acl\_tags\_all](#output\_web\_acl\_tags\_all) | Tags assigned to the Web ACL |
<!-- END_TF_DOCS -->
