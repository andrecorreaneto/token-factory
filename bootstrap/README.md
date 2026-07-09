# Token Factory Bootstrap

This Terraform module provisions the OCI and Identity Domain prerequisites for [Token Factory](../README.md). It outputs the runtime configuration that hosting applications plug into their environment.

It is recommended to run this module from the [client folder](./client/), which contains a runnable example driven from [terraform.tfvars.template](./client/terraform.tfvars.template).

This module manages:

- Shared Token Factory runtime configuration.
- One Identity Domain confidential OAuth client per `oauth_apps` entry.
- Identity Domain OAuth partner certificates.
- Optional IdentityPropagationTrust resources.
- Optional generated JWT private keys and self-signed certificates.
- Optional OCI Vault, master key, and secrets.
- Runtime IAM principals: dynamic groups or user groups.
- IAM policies granting `read secret-bundle` to runtime principals.
- `TF_SHARED_*`, `TF_CLIENT_*`, OAuth client resolver config, and resource OCID outputs.

## Mental Model

```text
shared Token Factory config + N oauth_apps entries = Token Factory bootstrap
```

Token Factory is not the OAuth client. Each hosting application is both:

- the OAuth confidential client used for outbound token exchange, introspection authentication, and UPST-backed flows;
- the resource-server boundary for incoming end-user access tokens.

Adding a new hosting application should be additive: add one `oauth_apps` entry and apply.

## Module Inputs

### Shared Inputs

| Variable | Type | Default | Required? | Description |
| --- | --- | --- | --- | --- |
| `region` | `string` | `null` | No | OCI provider region. Defaults to `identity_domain_region` when omitted. |
| `tenancy_ocid` | `string` | None | Yes | Tenancy OCID where IAM dynamic groups, groups, and policies are created. |
| `user_ocid` | `string` | `null` | No | Optional OCI API-key user OCID for local Terraform runs. |
| `fingerprint` | `string` | `null` | No | Optional OCI API-key fingerprint for local Terraform runs. |
| `private_key_path` | `string` | `null` | No | Optional OCI API private key path for local Terraform runs. |
| `private_key_password` | `string` | `null` | No | Optional OCI API private key password for local Terraform runs. Sensitive. |
| `resource_name_prefix` | `string` | `"token-factory"` | No | Prefix for shared Token Factory resource names. `null` or empty falls back to `token-factory`. |
| `identity_domain_url` | `string` | None | Yes | Identity Domain base URL. |
| `identity_domain_region` | `string` | None | Yes | OCI region used for token exchange and Identity Domain data-plane calls. |
| `enable_oci_secrets` | `bool` | `true` | No | When true, store OAuth app material in OCI Secrets and output secret OCIDs. |
| `oci_secrets_compartment_ocid` | `string` | `null` | Conditional | Compartment for created or existing OCI Secrets and runtime secret-read policies. Required when secrets are enabled. |
| `oci_vault_existing_ocid` | `string` | `null` | No | Existing Vault OCID. When omitted and secrets are enabled, the module provisions a Vault. |
| `oci_master_key_existing_ocid` | `string` | `null` | No | Existing Vault master key OCID. When omitted and secrets are enabled, the module provisions a key. |
| `oci_secrets_region` | `string` | `null` | No | Fallback OCI Secrets region for runtime config. Defaults to `identity_domain_region` when omitted. |
| `restrict_secret_policy_to_secret_ocids` | `bool` | `false` | No | When true, generated Vault read policies include where clauses for individual secret OCIDs. |

### Runtime Config Inputs

| Variable | Type | Default | Runtime output |
| --- | --- | --- | --- |
| `token_factory_timeout_seconds` | `number` | `30` | `TF_SHARED_TIMEOUT_SECONDS` |
| `token_factory_subject_claim` | `string` | `"sub"` | `TF_SHARED_SUBJECT_CLAIM` |
| `token_factory_groups_claim` | `string` | `"group"` | `TF_SHARED_GROUPS_CLAIM` |
| `token_factory_log_full_assertion` | `bool` | `false` | `TF_SHARED_LOG_FULL_ASSERTION`, only when true |
| `token_factory_authz_policy_secret_ocid` | `string` | `null` | `TF_SHARED_AUTHZ_POLICY_SECRET_OCID` |
| `token_factory_authz_policy_signature_mode` | `string` | `"off"` | `TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE` |
| `token_factory_authz_policy_trusted_signers` | `list(object)` | `[]` | `TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON` |
| `token_factory_authz_policy_environment` | `string` | `null` | `TF_SHARED_AUTHZ_POLICY_ENVIRONMENT` |
| `emit_authz_policy_tenant_id` | `bool` | `false` | `TF_SHARED_AUTHZ_POLICY_TENANT_ID`, only when true |

`token_factory_authz_policy_trusted_signers` entries have this shape:

```hcl
{
  key_id         = "ocid1.key.oc1..."
  key_version_id = "ocid1.keyversion.oc1..."
  algorithm      = "SHA_256_RSA_PKCS_PSS"
  public_key_pem = "-----BEGIN PUBLIC KEY-----..."
}
```

The module does not create the authorization matrix signing key. That key is security-owned; this module only accepts trusted public verifier metadata.

### OAuth App Inputs

`oauth_apps` is a map. Each entry represents one hosting application's Identity Domain OAuth confidential app and the runtime configuration Token Factory needs to use it.

Map keys are the canonical Token Factory `CallerContext.client_key` values and must be uppercase.

| Field | Required? | Description |
| --- | --- | --- |
| `resource_name_prefix` | No | Optional prefix for this app's resources. Defaults to the normalized map key, for example `MCP_SERVER` becomes `mcp-server`. |
| `display_name` | Yes | Identity Domain confidential app display name. |
| `description` | No | Identity Domain confidential app description. |
| `issuer` | Yes | JWT assertion issuer for this OAuth app/client identity. |
| `kid` | Yes | JWT key ID and OAuth partner certificate alias. |
| `resource_audiences` | Yes | Accepted incoming token audiences for this hosting app/resource server. |
| `resource_scopes` | No | Incoming Identity Domain resource-server scopes. Non-empty values make the Identity Domain app an OAuth resource. |
| `allowed_scopes` | No | OAuth client authorized scopes for the Identity Domain app. Values must be Identity Domain FQS strings. |
| `app_roles` | No | Identity Domain app-role grants for the OAuth app. Defaults to no grants. |
| `runtime.principal_type` | Yes | `compute-instance`, `oci-function`, `oke-cluster`, or `user-group`. |
| `runtime.compartment_ocid` | Yes | Compartment for dynamic group matching or group/policy placement. |
| `runtime.resource_ocid` | No | Optional exact compute instance, OCI Function, or OKE cluster OCID. |
| `runtime.oci_auth_profile` | No | Used only when `principal_type = "user-group"`; defaults to `DEFAULT` in runtime config. |
| `runtime.oci_region` | No | Per-runtime `TF_SHARED_OCI_REGION`; falls back to `oci_secrets_region` or `identity_domain_region`. |
| `enable_identity_propagation_trust` | No | Create IdentityPropagationTrust for `oracle-database` and `oci-service` UPST flows. Defaults to true. |
| `propagation_trust_claim_name` | No | Optional trust client claim name. Must be set with `propagation_trust_claim_value`. |
| `propagation_trust_claim_value` | No | Optional trust client claim value. Must be set with `propagation_trust_claim_name`. |
| `jwt_key_material_source` | No | `generate`, `provided_pem`, or `existing_secret_ocids`. Defaults to `generate`. |
| `jwt_private_key_pem` | Conditional | Private key PEM. Required when `jwt_key_material_source = "provided_pem"`. Sensitive. |
| `jwt_private_key_passphrase` | No | Optional private key passphrase. Sensitive. |
| `jwt_certificate_pem` | Conditional | Certificate PEM. Required when `jwt_key_material_source = "provided_pem"`. Sensitive. |
| `jwt_certificate_pem_for_identity_domain` | Conditional | Public certificate PEM for Identity Domains when using existing secret OCIDs. |
| `private_key_secret_existing_ocid` | Conditional | Existing private key secret OCID when `jwt_key_material_source = "existing_secret_ocids"`. |
| `private_key_passphrase_secret_existing_ocid` | No | Optional existing private key passphrase secret OCID. |
| `certificate_secret_existing_ocid` | Conditional | Existing certificate secret OCID when `jwt_key_material_source = "existing_secret_ocids"`. |

Supported `app_roles` values are Identity Domain app role display names validated by the module, such as `Me`, `User Administrator`, `Security Administrator`, and `Application Administrator`.

## Resource Name Prefix

The top-level `resource_name_prefix` defaults to `token-factory`. It affects shared resources only.

| Resource | Generated value with default prefix | When it applies |
| --- | --- | --- |
| `oci_kms_vault.this` | `token-factory-vault` | When `enable_oci_secrets = true` and `oci_vault_existing_ocid = null`. |
| `oci_kms_key.this` | `token-factory-master-key` | When `enable_oci_secrets = true` and `oci_master_key_existing_ocid = null`. |

Per-app resources use `oauth_apps[*].resource_name_prefix`. When it is omitted, the module normalizes the `oauth_apps` map key.

For `MCP_SERVER`, the default per-app prefix is `mcp-server`.

| Resource | Example generated value | When it applies |
| --- | --- | --- |
| `oci_identity_domains_app.these` | `mcp-server-client` | For each `oauth_apps` entry. |
| `oci_identity_domains_identity_propagation_trust.these` | `mcp-server-identity-propagation-trust` | When propagation trust is enabled for the app. |
| `oci_identity_dynamic_group.these` | `mcp-server-runtime-dynamic-group` | For compute, function, and OKE runtimes. |
| `oci_identity_group.these` | `mcp-server-runtime-user-group` | For `user-group` runtimes. |
| `oci_identity_policy.these` | `mcp-server-secrets-policy` | For each app runtime. |
| `oci_vault_secret.client_credentials` | `mcp-server-client-credentials-secret` | When `enable_oci_secrets = true`. |
| `oci_vault_secret.private_keys` | `mcp-server-jwt-private-key-secret` | When secrets are enabled and key material is generated or provided. |
| `oci_vault_secret.private_key_passphrases` | `mcp-server-jwt-private-key-passphrase-secret` | When a passphrase secret is needed. |
| `oci_vault_secret.certificates` | `mcp-server-jwt-certificate-secret` | When secrets are enabled and key material is generated or provided. |

## Module Outputs

| Output | Description |
| --- | --- |
| `token_factory_shared_runtime_config` | Shared runtime config base. Excludes OAuth app identity fields and per-runtime OCI auth values. |
| `token_factory_runtime_configs` | Full Token Factory runtime configuration by OAuth app key. |
| `token_factory_runtime_config_env` | Shell `export` lines for `TF_SHARED_*` runtime configuration by OAuth app key. |
| `token_factory_client_config_env` | Shell `export` lines for `TF_CLIENT_*` OAuth client configuration by OAuth app key. Contains secret OCID references, not inline secrets. |
| `token_factory_client_sensitive_config_env` | Sensitive shell `export` lines for `TF_CLIENT_*` OAuth client configuration, including inline credentials and PEM values when `enable_oci_secrets = false`. |
| `oauth_app_configs` | Non-sensitive `OAuthClientInfo`-shaped resolver config by OAuth app key. Contains secret OCID references, not inline secrets. |
| `oauth_app_configs_json` | JSON-encoded non-sensitive resolver config for Vault-backed deployments. |
| `oauth_app_sensitive_configs` | Sensitive resolver config including inline credentials and PEM values when `enable_oci_secrets = false`. |
| `oauth_app_sensitive_configs_json` | JSON-encoded sensitive resolver config for direct-value deployments. |
| `oauth_app_runtime_secret_ocids` | OAuth material secret OCIDs each OAuth app runtime must read. |
| `runtime_secret_ocids` | Authz policy secret plus OAuth app secret OCIDs by OAuth app key. |
| `runtime_principals` | Runtime IAM principal details by OAuth app key. |
| `secret_policy_statements` | Generated Vault read policy statements by OAuth app key. |
| `oauth_app_resource_ids` | App, grant, certificate, trust, IAM, and secret IDs by OAuth app key. |
| `provisioned_resource_ids` | Combined shared and OAuth app/runtime resource IDs. |
| `provisioned_resources` | Shared and OAuth app/runtime resources with names and OCIDs for lookup. |

Regular outputs intentionally avoid inline credentials and PEM values. Direct-value resolver outputs are marked sensitive.

## Vault and Secrets

Vault-backed mode is the default. Set `enable_oci_secrets = true` and provide `oci_secrets_compartment_ocid`.

The module can create a Vault and master key, or use existing ones:

```hcl
oci_vault_existing_ocid      = var.vault_ocid
oci_master_key_existing_ocid = var.master_key_ocid
```

To use an existing Vault but let the module create a new master key in it:

```hcl
oci_vault_existing_ocid = var.vault_ocid
```

Providing `oci_master_key_existing_ocid` without `oci_vault_existing_ocid` is invalid.

Vault-backed deployments should use `oauth_app_configs_json` for constructor-based configuration or `token_factory_client_config_env` for environment-based configuration. Both outputs contain resolver config with secret OCID references.

Direct-value deployments set `enable_oci_secrets = false` and use `oauth_app_sensitive_configs_json` or `token_factory_client_sensitive_config_env`. Terraform redacts those outputs by default.

## Key Material Sources

`jwt_key_material_source` is configured per OAuth app.

Supported values:

- `generate`: Terraform generates an RSA private key and self-signed certificate.
- `provided_pem`: callers provide `jwt_private_key_pem` and `jwt_certificate_pem`.
- `existing_secret_ocids`: callers provide existing private key and certificate secret OCIDs plus `jwt_certificate_pem_for_identity_domain`.

When `enable_oci_secrets = false`, OCI secrets, runtime IAM groups, and runtime IAM policies are not created. In direct-value mode, Token Factory does not need OCI IAM access just to load its own configuration.

## Runtime IAM

Runtime IAM is configured per OAuth app with `oauth_apps[*].runtime.principal_type`.

| `runtime.principal_type` | `TF_SHARED_OCI_AUTH_MODE` | Principal created |
| --- | --- | --- |
| `compute-instance` | `instance-principal` | Dynamic group |
| `oci-function` | `resource-principal` | Dynamic group |
| `oke-cluster` | `resource-principal` | Dynamic group |
| `user-group` | `oci-profile` | User group |

Set `runtime.compartment_ocid` for every app. Optionally set `runtime.resource_ocid` to restrict dynamic group matching to one compute instance, OKE cluster, or OCI Function.

For `user-group`, the module creates the group and policy but does not manage user membership. Add the intended API-key user through your normal IAM process.

## Security Notes

Generated and provided private key material is stored in Terraform state. Prefer Vault-backed mode for production.

Use `jwt_key_material_source = "existing_secret_ocids"` when Terraform should not handle raw private key material.

`resource_scopes` are incoming resource-server scopes for the hosting application. They are not downstream scopes requested from target tools.

`allowed_scopes` are the OAuth client scopes authorized on the Identity Domain app. Pass Identity Domain FQS strings directly.

Downstream target-tool authorization is optionally controlled by security policy in the Token Factory authorization policy secret.
