# Token Factory Bootstrap

This terraform module provisions the OCI and Identity Domain prerequisites of [Token Factory](../README.md) and outputs the runtime configuration that applications plug into their environment.

It is recommended to run this module from [client folder](./client/).

It manages:

- Identity Domain confidential OAuth client.
- Identity Domain OAuth partner certificate.
- IdentityPropagationTrust.
- optional generated JWT private key and self-signed certificate.
- optional OCI Vault, master key, and secrets.
- IAM principal: dynamic group or user group.
- IAM policy granting *read secret-bundle* to the IAM principal.
- `TOKEN_FACTORY_*` and resource OCIDs outputs.

## Module Inputs

| Variable | Type | Default | Required? | Description |
| --- | --- | --- | --- | --- |
| `region` | `string` | `null` | Yes | OCI region where Token Factory regional resources (like vault, master key and secrets) are managed. |
| `tenancy_ocid` | `string` | None | Yes | Tenancy OCID where module-managed IAM dynamic groups, groups, and policies are created. |
| `user_ocid` | `string` | `null` | Yes | OCI API-key user OCID for local Terraform runs. |
| `fingerprint` | `string` | `null` | Yes | OCI API-key fingerprint for local Terraform runs. |
| `private_key_path` | `string` | `null` | Yes | OCI API private key path for local Terraform runs. |
| `private_key_password` | `string` | `null` | No | Optional OCI API private key password for local Terraform runs. Sensitive. |
| `resource_name_prefix` | `string` | `"token-factory"` | No | Prefix used for module-managed resource names. The value is lowercased, trimmed, and has spaces and underscores converted to hyphens. See the next table for affected resources. |
| `identity_domain_name` | `string` | None | Yes | Identity Domain name used for Token Factory OAuth client, certificate, propagation trust resources, groups and dynamic groups (unless overridden by `identity_domain_name_for_groups`). The module resolves the domain URL internally. |
| `identity_domain_name_for_groups` | `string` | `null` | No | Identity Domain name used for generated runtime groups and dynamic groups. Defaults to `identity_domain_name` if not provided. |
| `identity_domain_region` | `string` | None | Yes | OCI Identity region. Used by TokenFactory for token exchange and identity data plane calls. |
| `token_factory_issuer` | `string` | `"https://upst.tokenfactory/"` | No | JWT issuer and IdentityPropagationTrust issuer. |
| `token_factory_kid` | `string` | `"token-factory-cert"` | No | Certificate alias and JWT `kid` header value. |
| `identity_propagation_trust_claim_name` | `string` | `null` | No | Optional IdentityPropagationTrust client claim name. Must be set together with `identity_propagation_trust_claim_value`. |
| `identity_propagation_trust_claim_value` | `string` | `null` | No | Optional IdentityPropagationTrust client claim value. Must be set together with `identity_propagation_trust_claim_name`. |
| `enable_oci_secrets` | `bool` | `true` | No | When true, store sensitive runtime values in OCI Secrets and output secret OCIDs. |
| `jwt_key_material_source` | `string` | `"generate"` | No | Source for JWT private key and certificate material. Valid values: `generate`, `provided_pem`, `existing_secret_ocids`. |
| `oci_secrets_compartment_ocid` | `string` | `null` | Conditional | Compartment for created or existing OCI Secrets. Required when `enable_oci_secrets = true`. |
| `oci_vault_existing_ocid` | `string` | `null` | No | Existing Vault OCID to use. When omitted and secrets are enabled, the module provisions a Vault. |
| `oci_master_key_existing_ocid` | `string` | `null` | No | Existing Vault master encryption key OCID to use. When omitted and secrets are enabled, the module provisions a master key. Can be set only with `oci_vault_existing_ocid`. |
| `oci_secrets_region` | `string` | `null` | No | Region TokenFactory should use for OCI Secrets access. Feeds `TOKEN_FACTORY_OCI_REGION`; defaults to `identity_domain_region` when omitted and secrets are enabled. |
| `oci_private_key_secret_existing_ocid` | `string` | `null` | Conditional | Existing OCI Secret OCID for private key PEM when `jwt_key_material_source = "existing_secret_ocids"`. |
| `oci_private_key_passphrase_secret_existing_ocid` | `string` | `null` | No | Existing OCI Secret OCID for private-key passphrase. |
| `oci_certificate_secret_existing_ocid` | `string` | `null` | Conditional | Existing OCI Secret OCID for certificate PEM when `jwt_key_material_source = "existing_secret_ocids"`. |
| `jwt_private_key_pem` | `string` | `null` | Conditional | Caller-provided JWT signing private key PEM when `jwt_key_material_source = "provided_pem"`. Sensitive. |
| `jwt_private_key_passphrase` | `string` | `null` | No | Optional passphrase for the JWT signing private key. Sensitive. |
| `jwt_certificate_pem` | `string` | `null` | Conditional | Caller-provided X.509 certificate PEM when `jwt_key_material_source = "provided_pem"`. Sensitive. |
| `jwt_certificate_pem_for_identity_domain` | `string` | `null` | Conditional | Public X.509 certificate PEM used to configure Identity Domains when `jwt_key_material_source = "existing_secret_ocids"`. |
| `token_factory_client_display_name` | `string` | `"token-factory-client"` | No | Display name for the generated confidential OAuth app client. This is not derived from `resource_name_prefix`. |
| `token_factory_client_description` | `string` | `"Token Factory confidential OAuth client."` | No | Description for the generated confidential OAuth app client. |
| `token_factory_runtime_iam_auth_mode` | `string` | `"instance-principal"` | No | Runtime OCI authentication mode. Valid values: `instance-principal`, `resource-principal`, `oci-profile`. |
| `token_factory_runtime_iam_principal_type` | `string` | `"compute-instance"` | No | Runtime principal type. Valid values: `compute-instance`, `oci-function`, `oke-cluster`, `user-group`. |
| `token_factory_runtime_compartment_ocid` | `string` | `null` | Conditional | Compartment used by generated runtime IAM matching rules. Required for instance-principal and resource-principal runtime IAM when secrets are enabled. |
| `token_factory_runtime_resource_ocid` | `string` | `null` | No | Optional OCID restricting the generated runtime IAM rule to one compute instance, OKE cluster, or OCI Function. Must be omitted for `user-group`. |
| `restrict_secret_policy_to_secret_ocids` | `bool` | `false` | No | When true, generated Vault read policies include where clauses for individual secret OCIDs. |

## Resource Name Prefix

`resource_name_prefix` defaults to `token-factory`. The module normalizes it by trimming whitespace, lowercasing it, and replacing spaces and underscores with hyphens before composing managed resource names.

| Resource | Attribute | Generated value with default prefix | When it applies |
| --- | --- | --- | --- |
| `oci_identity_domains_app.client` | `name` | `token-factory-client` | Always. |
| `oci_identity_domains_identity_propagation_trust.jwt` | `name` | `token-factory-identity-propagation-trust` | Always. |
| `oci_kms_vault.this` | `display_name` | `token-factory-vault` | When `enable_oci_secrets = true` and `oci_vault_existing_ocid = null`. |
| `oci_kms_key.this` | `display_name` | `token-factory-master-key` | When `enable_oci_secrets = true` and `oci_master_key_existing_ocid = null`. |
| `oci_vault_secret.client_credentials` | `secret_name` | `token-factory-client-credentials` | When `enable_oci_secrets = true`. |
| `oci_vault_secret.private_key` | `secret_name` | `token-factory-jwt-private-key` | When `enable_oci_secrets = true` and `jwt_key_material_source` is `generate` or `provided_pem`. |
| `oci_vault_secret.private_key_passphrase` | `secret_name` | `token-factory-jwt-private-key-passphrase` | When `enable_oci_secrets = true`, `jwt_key_material_source` is `generate` or `provided_pem`, and `jwt_private_key_passphrase` is set. |
| `oci_vault_secret.certificate` | `secret_name` | `token-factory-jwt-certificate` | When `enable_oci_secrets = true` and `jwt_key_material_source` is `generate` or `provided_pem`. |
| `oci_identity_dynamic_group.runtime` or `oci_identity_domains_dynamic_resource_group.runtime` | `name` / `display_name` | `token-factory-instance-principal-dynamic-group` | When `enable_oci_secrets = true` and `token_factory_runtime_iam_principal_type = "compute-instance"`. |
| `oci_identity_dynamic_group.runtime` or `oci_identity_domains_dynamic_resource_group.runtime` | `name` / `display_name` | `token-factory-oke-cluster-dynamic-group` | When `enable_oci_secrets = true` and `token_factory_runtime_iam_principal_type = "oke-cluster"`. |
| `oci_identity_dynamic_group.runtime` or `oci_identity_domains_dynamic_resource_group.runtime` | `name` / `display_name` | `token-factory-functions-dynamic-group` | When `enable_oci_secrets = true` and `token_factory_runtime_iam_principal_type = "oci-function"`. |
| `oci_identity_group.runtime` or `oci_identity_domains_group.runtime` | `name` / `display_name` | `token-factory-api-key-group` | When `enable_oci_secrets = true` and `token_factory_runtime_iam_principal_type = "user-group"`. |
| `oci_identity_policy.secrets` | `name` | `token-factory-secrets-policy` | When `enable_oci_secrets = true`. |

## Module Outputs

- **token_factory_config_env**: TokenFactory runtime configuration variables. Share them with TokenFactory runtime.

Example:
```
export TOKEN_FACTORY_CERT_SECRET_OCID="ocid1.vaultsecret.oc1.us-chicago-1....4sma"
export TOKEN_FACTORY_CREDS_SECRET_OCID="ocid1.vaultsecret.oc1.us-chicago-1....goja"
export TOKEN_FACTORY_DOMAIN_REGION="us-chicago-1"
export TOKEN_FACTORY_DOMAIN_URL="https://idcs-1a15d6dbb17....c6bf5e414d8.identity.oraclecloud.com:443"
export TOKEN_FACTORY_ISSUER="https://token.factory/"
export TOKEN_FACTORY_KID="tf-cert"
export TOKEN_FACTORY_OCI_AUTH_MODE="instance-principal"
export TOKEN_FACTORY_OCI_REGION="us-chicago-1"
export TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID="ocid1.vaultsecret.oc1.us-chicago-1....g66q"
```

- **provisioned_resources_ids**: The provisioned OCI resource OCIDs. Use them to look up the provisioned resources in OCI.

Example:
```
  "identity_domain_app_id" = "dd27b920....fc7f0dc30861"
  "identity_domain_certificate_id" = "5b48089....a3320f173ab099"
  "identity_propagation_trust_id" = "4012c89....2e342be24176f84"
  "oci_certificate_secret_ocid" = "ocid1.vaultsecret.oc1.us-chicago-1....4sma"
  "oci_master_key_id" = "ocid1.key.oc1.us-chicago-1.ijvamajzaaeow....w77a"
  "oci_private_key_passphrase_secret_ocid" = tostring(null)
  "oci_private_key_secret_ocid" = "ocid1.vaultsecret.oc1.us-chicago-1....g66q"
  "oci_vault_id" = "ocid1.vault.oc1.us-chicago-1.ijvamajzaaeow....n4iq"
  "runtime_dynamic_group_id" = "ocid1.dynamicgroup.oc1.....q3wq"
  "runtime_group_id" = null
  "runtime_policy_id" = "ocid1.policy.oc1.....nqia"
  "token_factory_creds_secret_ocid" = "ocid1.vaultsecret.oc1.us-chicago-1....goja"
```  

## Vault and Secrets

Vault-backed mode outputs secret OCIDs such as `TOKEN_FACTORY_CREDS_SECRET_OCID`, `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID`, and `TOKEN_FACTORY_CERT_SECRET_OCID`. 

Direct mode outputs direct values such as `TOKEN_FACTORY_CREDS`, `TOKEN_FACTORY_PRIVATE_KEY_PEM`, and `TOKEN_FACTORY_CERT_PEM`.

By default, `enable_oci_secrets = true` and the module provisions a Vault and master key in `oci_secrets_compartment_ocid`.

To use an existing Vault and key:

```hcl
oci_vault_existing_ocid      = var.vault_ocid
oci_master_key_existing_ocid = var.master_key_ocid
```

To use an existing Vault but let the module create a new master key in it:

```hcl
oci_vault_existing_ocid = var.vault_ocid
```

Providing `oci_master_key_existing_ocid` without `oci_vault_existing_ocid` is invalid.

## Key Material Sources

`jwt_key_material_source` supports:

- `generate`: Terraform generates an RSA private key and self-signed certificate.
- `provided_pem`: callers provide `jwt_private_key_pem` and `jwt_certificate_pem`.
- `existing_secret_ocids`: callers provide `oci_private_key_secret_existing_ocid`, optional `oci_private_key_passphrase_secret_existing_ocid`, `oci_certificate_secret_existing_ocid`, and `jwt_certificate_pem_for_identity_domain`.

When `enable_oci_secrets = false`, OCI secrets, dynamic groups, groups, and policies are not created. In that direct-value mode, TokenFactory does not need OCI IAM access just to load its own configuration.

## Runtime IAM

The module derives runtime IAM from the selected auth mode:

```hcl
# Compute instance principals, default.
token_factory_runtime_iam_auth_mode      = "instance-principal"
token_factory_runtime_iam_principal_type = "compute-instance"

# OKE resource principals.
token_factory_runtime_iam_auth_mode      = "resource-principal"
token_factory_runtime_iam_principal_type = "oke-cluster"
token_factory_runtime_resource_ocid      = var.oke_cluster_ocid

# OCI Functions resource principals.
token_factory_runtime_iam_auth_mode      = "resource-principal"
token_factory_runtime_iam_principal_type = "oci-function"
token_factory_runtime_resource_ocid      = var.function_ocid

# OCI API-key profile runtimes.
token_factory_runtime_iam_auth_mode      = "oci-profile"
token_factory_runtime_iam_principal_type = "user-group"
```

For instance-principal and resource-principal modes, set `token_factory_runtime_compartment_ocid`; optionally set `token_factory_runtime_resource_ocid` to restrict the generated dynamic group to one compute instance, OKE cluster, or function.

For `oci-profile`, the module creates an OCI user group and policy but does not manage user membership. Add the intended API-key user to the generated group through your normal IAM process.

Generated runtime groups and dynamic groups are created in `identity_domain_name` by default. Set `identity_domain_name_for_groups` to another Identity Domain name to create them in a different domain. The module uses tenancy IAM group resources for the Default domain and Identity Domains group resources for non-default domains. When the selected group domain is not Default, generated IAM policy statements use the `'identity-domain-name'/'group-name'` or `'identity-domain-name'/'dynamic-group-name'` subject syntax.

## Security Notes

Generated and provided private key material is stored in Terraform state. Prefer `enable_oci_secrets = true` for production, and use `jwt_key_material_source = "existing_secret_ocids"` when Terraform should not handle raw private key material.

## Smallest Configuration Example

```hcl
module "token_factory_bootstrap" {
  source = "../"

  tenancy_ocid           = var.tenancy_ocid
  identity_domain_name   = "replace-with-identity-domain-name"
  identity_domain_region = "us-chicago-1"

  oci_secrets_compartment_ocid           = "replace-with-secrets-compartment-ocid"
  token_factory_runtime_compartment_ocid = "replace-with-token-factory-runtime-compartment-ocid"
}
```

Defaults used by the example:

- `enable_oci_secrets = true`
- `jwt_key_material_source = "generate"`
- `token_factory_issuer = "https://upst.tokenfactory/"`
- `token_factory_kid = "token-factory-cert"`
- `token_factory_runtime_iam_auth_mode = "instance-principal"`
- `token_factory_runtime_iam_principal_type = "compute-instance"`
- `oci_vault_existing_ocid = null`, so the module provisions `token-factory-vault`
- `oci_master_key_existing_ocid = null`, so the module provisions `token-factory-master-key`
