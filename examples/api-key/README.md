# AWS WAFv2 API Key Example

Configuration in this directory creates a WAFv2 API Key for CAPTCHA / JavaScript challenge integration on a set of token domains.

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

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_api_key"></a> [api\_key](#module\_api\_key) | ../../modules/api-key | n/a |
| <a name="module_disabled"></a> [disabled](#module\_disabled) | ../../modules/api-key | n/a |

## Resources

No resources.

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_key"></a> [api\_key](#output\_api\_key) | The generated API key (sensitive) |
| <a name="output_token_domains"></a> [token\_domains](#output\_token\_domains) | The token domains the API key is bound to |
<!-- END_TF_DOCS -->
