# AWS WAF v2 Logging Configuration Submodule

Terraform submodule which creates an AWS WAF v2 logging configuration.

## Usage

```hcl
module "logging_configuration" {
  source = "terraform-aws-modules/wafv2/aws//modules/logging-configuration"

  resource_arn            = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/12345678-1234-1234-1234-123456789012"
  log_destination_configs = ["arn:aws:s3:::aws-waf-logs-my-bucket"]

  redacted_fields = [
    {
      single_header = {
        name = "authorization"
      }
    }
  ]
}
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

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_wafv2_web_acl_logging_configuration.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created | `bool` | `true` | no |
| <a name="input_log_destination_configs"></a> [log\_destination\_configs](#input\_log\_destination\_configs) | The Amazon Kinesis Data Firehose, CloudWatch Log Group, or S3 Bucket Amazon Resource Names (ARNs) that you want to associate with the Web ACL. Names must be prefixed with `aws-waf-logs-` | `list(string)` | n/a | yes |
| <a name="input_logging_filter"></a> [logging\_filter](#input\_logging\_filter) | A configuration block that specifies which web requests are kept in the logs and which are dropped | <pre>object({<br/>    default_behavior = string<br/>    filters = list(object({<br/>      behavior    = string<br/>      requirement = string<br/>      conditions = list(object({<br/>        action_condition = optional(object({<br/>          action = string<br/>        }))<br/>        label_name_condition = optional(object({<br/>          label_name = string<br/>        }))<br/>      }))<br/>    }))<br/>  })</pre> | `null` | no |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_redacted_fields"></a> [redacted\_fields](#input\_redacted\_fields) | The parts of the request that you want to keep out of the logs. Each entry must specify exactly one of `method`, `query_string`, `uri_path`, or `single_header` | <pre>list(object({<br/>    method        = optional(object({}))<br/>    query_string  = optional(object({}))<br/>    uri_path      = optional(object({}))<br/>    single_header = optional(object({ name = string }))<br/>  }))</pre> | `[]` | no |
| <a name="input_region"></a> [region](#input\_region) | Region where the WAF logging configuration will be managed. Defaults to the provider region | `string` | `null` | no |
| <a name="input_resource_arn"></a> [resource\_arn](#input\_resource\_arn) | The ARN of the Web ACL to associate with the logging configuration | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_id"></a> [id](#output\_id) | The ID of the WAF logging configuration |
| <a name="output_resource_arn"></a> [resource\_arn](#output\_resource\_arn) | The ARN of the Web ACL associated with the logging configuration |
<!-- END_TF_DOCS -->
