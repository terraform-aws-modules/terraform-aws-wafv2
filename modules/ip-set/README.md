# AWS WAF v2 IP Set Submodule

Terraform submodule which creates an AWS WAF v2 IP set.

## Usage

```hcl
module "ip_set" {
  source = "terraform-aws-modules/wafv2/aws//modules/ip-set"

  name               = "my-ip-set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = [
    "10.0.0.0/8",
    "192.168.0.0/16",
  ]

  tags = {
    Environment = "dev"
  }
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
| [aws_wafv2_ip_set.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_addresses"></a> [addresses](#input\_addresses) | Contains an array of strings that specifies zero or more IP addresses or blocks of IP addresses in CIDR notation | `list(string)` | `[]` | no |
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created | `bool` | `true` | no |
| <a name="input_description"></a> [description](#input\_description) | A friendly description of the IP set | `string` | `null` | no |
| <a name="input_ip_address_version"></a> [ip\_address\_version](#input\_ip\_address\_version) | Specify `IPV4` or `IPV6`. Valid values are `IPV4` or `IPV6` | `string` | `"IPV4"` | no |
| <a name="input_name"></a> [name](#input\_name) | A friendly name of the IP set | `string` | n/a | yes |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL` | `string` | `"REGIONAL"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arn"></a> [arn](#output\_arn) | The ARN of the IP set |
| <a name="output_id"></a> [id](#output\_id) | The ID of the IP set |
| <a name="output_lock_token"></a> [lock\_token](#output\_lock\_token) | A token used for optimistic locking |
| <a name="output_tags_all"></a> [tags\_all](#output\_tags\_all) | A map of tags assigned to the resource, including those inherited from the provider default\_tags configuration block |
<!-- END_TF_DOCS -->
