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
- Runtime IAM principals: dynamic groups or user groups in the Default domain, or Identity Domain groups/dynamic resource groups in a custom domain.
- IAM policies granting `read secret-bundle` to runtime principals.
- Optional IAM policies granting database connectivity access to runtime dynamic groups.
- Shared runtime config, per-client runtime config, and resource lookup outputs.

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
| `tenancy_ocid` | `string` | None | Yes | Tenancy OCID used for Identity Domain lookup and Default-domain IAM groups, dynamic groups, and policies. |
| `user_ocid` | `string` | `null` | No | Optional OCI API-key user OCID for local Terraform runs. |
| `fingerprint` | `string` | `null` | No | Optional OCI API-key fingerprint for local Terraform runs. |
| `private_key_path` | `string` | `null` | No | Optional OCI API private key path for local Terraform runs. |
| `private_key_password` | `string` | `null` | No | Optional OCI API private key password for local Terraform runs. Sensitive. |
| `resource_name_prefix` | `string` | `"token-factory"` | No | Prefix for shared Token Factory resource names. `null` or empty falls back to `token-factory`. |
| `identity_domain_url` | `string` | None | Yes | Identity Domain base URL. Determines whether runtime principals are created in the Default domain or a custom Identity Domain. |
| `identity_domain_region` | `string` | None | Yes | OCI region used for token exchange and Identity Domain data-plane calls. |
| `enable_oci_secrets` | `bool` | `true` | No | When true, store OAuth app material in OCI Secrets and output secret OCIDs. |
| `oci_secrets_compartment_ocid` | `string` | `null` | Conditional | Compartment for created or existing OCI Secrets and runtime secret-read policies. Required when secrets are enabled. |
| `oci_vault_existing_ocid` | `string` | `null` | No | Existing Vault OCID. When omitted and secrets are enabled, the module provisions a Vault. |
| `oci_master_key_existing_ocid` | `string` | `null` | No | Existing Vault master key OCID. When omitted and secrets are enabled, the module provisions a key. |

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
| `resource_name_prefix` | No | Optional prefix for this app's resources. Defaults to normalized `display_name`; the map key remains only the Terraform identity. |
| `display_name` | Yes | Identity Domain confidential app display name. |
| `description` | No | Identity Domain confidential app description. |
| `issuer` | Yes | JWT assertion issuer for this OAuth app/client identity. |
| `kid` | Yes | JWT key ID and OAuth partner certificate alias. |
| `resource_audiences` | Yes | Accepted incoming token audiences for this hosting app/resource server. |
| `resource_scopes` | No | Incoming Identity Domain resource-server scopes. Non-empty values make the Identity Domain app an OAuth resource. |
| `allowed_scopes` | No | OAuth client authorized scopes for the Identity Domain app. Values must be Identity Domain FQS strings. Apps with allowed scopes are created after scope-independent apps so module-managed resource scopes exist first. |
| `app_roles` | No | Identity Domain app-role grants for the OAuth app. Defaults to no grants. |
| `allowed_clients` | No | Other `oauth_apps` keys whose OAuth clients may call this app. The module resolves them to client IDs and emits `allowed_client_ids` / `TF_CLIENT_ALLOWED_CLIENT_IDS`. Omit it to leave the runtime client check off. The app always accepts its own client ID, so `[]` means "only this app". Clients outside this module are configured on the runtime `allowed_client_ids` directly. |
| `compute_runtime` | Exactly one runtime | Exact Compute workload object containing `instance_ocid`. |
| `function_runtime` | Exactly one runtime | Exact Functions workload object containing `function_ocid`. |
| `oke_runtime` | Exactly one runtime | OKE workload identity containing `cluster_ocid`, `namespace`, and `service_account`. |
| `local_runtime` | Exactly one runtime | Local/API-key runtime with optional `oci_auth_profile`, defaulting to `DEFAULT`; discouraged for OCI-hosted workloads. |
| `database_access` | No | Runtime-independent sibling that creates a target-database-scoped `database-connections` policy and emits database-owner guidance. |
| `enable_identity_propagation_trust` | No | Create IdentityPropagationTrust for `oracle-database` and `oci-service` UPST flows. Defaults to true. |
| `propagation_trust_claim_name` | No | Optional trust client claim name. Must be set with `propagation_trust_claim_value`. |
| `propagation_trust_claim_value` | No | Optional trust client claim value. Must be set with `propagation_trust_claim_name`. |
| `signing_key.mode` | Yes | `BOOTSTRAP_MANAGED` creates a non-exportable RSA KMS key and registers its KMS-signed certificate. `EXTERNALLY_MANAGED` references an existing key/version. |
| `signing_key.signing_key_ocid` | External mode | Existing asymmetric KMS key OCID. |
| `signing_key.signing_key_version_ocid` | External mode; optional managed rotation | Exact KMS key-version OCID. Managed mode defaults to the created key's current version and accepts an explicit rotated version. |
| `signing_key.signing_certificate_pem` | External mode | Public certificate PEM; mutually exclusive with `signing_certificate_path`. |
| `signing_key.signing_certificate_path` | External mode | Public certificate file path; mutually exclusive with `signing_certificate_pem`. |

Supported `app_roles` values are Identity Domain app role display names validated by the module, such as `Me`, `User Administrator`, `Security Administrator`, and `Application Administrator`.

## Resource Name Prefix

The top-level `resource_name_prefix` defaults to `token-factory`. It affects shared resources only.

| Resource | Generated value with default prefix | When it applies |
| --- | --- | --- |
| `oci_kms_vault.this` | `token-factory-vault` | When `enable_oci_secrets = true` and `oci_vault_existing_ocid = null`. |
| `oci_kms_key.this` | `token-factory-master-key` | When `enable_oci_secrets = true` and `oci_master_key_existing_ocid = null`. |

Per-app resources use `oauth_apps[*].resource_name_prefix`. When it is omitted or empty, the module normalizes the app `display_name`.

For `MCP_SERVER`, the default per-app prefix is `mcp-server`.

| Resource | Example generated value | When it applies |
| --- | --- | --- |
| `oci_identity_domains_app.these` | `mcp-server-client` | For apps without `allowed_scopes`. |
| `oci_identity_domains_app.scope_consumers` | `agent-client` | For apps with `allowed_scopes`, after scope-independent apps. |
| `oci_identity_domains_identity_propagation_trust.these` | `mcp-server-identity-propagation-trust` | When propagation trust is enabled for the app. |
| `oci_identity_dynamic_group.these` | `mcp-server-runtime-dynamic-group` | For exact Compute and Function runtimes when `identity_domain_url` resolves to the Default domain. |
| `oci_identity_group.these` | `mcp-server-runtime-user-group` | For `user-group` runtimes when `identity_domain_url` resolves to the Default domain. |
| `oci_identity_domains_dynamic_resource_group.these` | `mcp-server-runtime-dynamic-group` | For exact Compute and Function runtimes when `identity_domain_url` resolves to a custom Identity Domain. |
| `oci_identity_domains_group.these` | `mcp-server-runtime-user-group` | For `user-group` runtimes when `identity_domain_url` resolves to a custom Identity Domain. |
| `oci_identity_policy.these` | `mcp-server-secrets-policy` | For each app runtime. |
| `oci_identity_policy.database_access` | `mcp-server-database-access-policy` | When sibling `database_access` is set. |
| `oci_vault_secret.client_credentials` | `mcp-server-client-credentials-secret` | When `enable_oci_secrets = true`. |
| `oci_kms_key.signing` | `mcp-server-jwt-signing-key` | For each `BOOTSTRAP_MANAGED` app. Private key material never leaves KMS. |

## Module Outputs

| Output | Description |
| --- | --- |
| `shared_runtime_config` | Shared Token Factory runtime config object. |
| `clients_runtime_config` | Per-client runtime config with client-credential Secret references, version-pinned KMS signing metadata, and optional database guidance. |
| `provisioned_resources` | Shared and OAuth app/runtime resources with names, OCIDs/IDs, generated policy statements, and selected Identity Domain metadata. |

Regular outputs intentionally avoid inline credentials and PEM values. Direct-value resolver outputs are marked sensitive.

## Vault and Secrets

Every OAuth app requires a shared OCI Vault for its asymmetric signing key. Set `enable_oci_secrets = true` when client credentials should also be stored as Vault Secrets.

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

Vault-backed deployments should use `shared_runtime_config` plus `clients_runtime_config[<client_key>]`. Callers can derive shell export lines from `shared_runtime_config` when a hosting runtime is configured through environment variables.

Direct client-credential deployments may set `enable_oci_secrets = false`; the Vault and constrained KMS IAM policies are still required for assertion signing.

## KMS Signing Modes

`BOOTSTRAP_MANAGED` creates an RSA KMS key in the shared Vault. The certificate utility obtains the exact key-version public key, self-signs through KMS Sign, and idempotently registers the OAuth partner certificate. KMS and Identity Domains operations use the same OCI identity and API-key or workload signer configured for the Terraform bootstrap runner.

Install the repository `requirements.txt` into the interpreter selected by `certificate_registration_python_command` before apply. Generate a fresh plan after changing the command or utility wiring because a saved plan retains its provisioner command.

`EXTERNALLY_MANAGED` requires an existing key OCID, exact key-version OCID, and one public certificate input. Bootstrap verifies that the certificate public key matches the selected KMS key version before registering it through Terraform.

Neither mode accepts or exports hosting private-key PEM.

Managed signing keys disable automatic rotation. Rotate explicitly in KMS, set the new `signing_key_version_ocid` and a new `kid`, publish the new certificate, deploy the version-pinned runtime configuration, and retire the prior certificate only after the rollout completes. The key OCID and its constrained IAM policy remain stable, so old and new key versions can overlap safely.

To retire the prior alias, invoke the certificate utility with `TF_CERT_ACTION=delete`, `TF_CERT_IDCS_ENDPOINT`, `TF_CERT_ALIAS`, and the bootstrap runner's OCI authentication environment after the rollout.

When `enable_oci_secrets = false`, client-credential Secrets and their read policies are omitted. Runtime identity and constrained KMS `use keys` policies remain required.

## Runtime IAM

Runtime IAM is derived from the one configured runtime object. `TF_SHARED_OCI_REGION` uses top-level `region`, falling back to `identity_domain_region`; runtime objects do not override it.

| Runtime object | `TF_SHARED_OCI_AUTH_MODE` | Principal created |
| --- | --- | --- |
| `compute_runtime` | `instance-principal` | Exact-instance dynamic group |
| `function_runtime` | `resource-principal` | Exact-function dynamic group |
| `oke_runtime` | `oke-workload-identity` | `any-user` policy constrained by cluster, namespace, and service account |
| `local_runtime` | `oci-profile` | User group |

Compute and Function runtime objects require an exact resource OCID. OKE uses its cluster/namespace/service-account workload tuple and does not create a dynamic group.

For `user-group`, the module creates the group and policy but does not manage user membership. Add the intended API-key user through your normal IAM process.

### Oracle Database Token Access

Set sibling `oauth_apps[*].database_access` when the runtime should call:

```python
factory.get_token("oracle-database", "OCI_PRINCIPAL", db_scope, client_key="MCP_SERVER")
```

The module creates a separate IAM policy for the runtime dynamic group and attaches it to `target_database_compartment_ocid`. The statement is:

```text
allow <dynamic-group-subject> to use database-connections in compartment id <target_database_compartment_ocid> where target.database.id = '<target_database_ocid>'
```

Default-domain policies use unquoted group names. Custom Identity Domain policies use quoted domain-qualified names, for example `dynamic-group 'example-domain'/'mcp-server-runtime-dynamic-group'`.

`database_access` provisions only the OCI IAM policy required to request database tokens. `clients_runtime_config[<client_key>].database_access` reports the target database, generated policy statements, and a requirement note. Database authentication enablement, schema mapping, users, roles, and grants remain owned by the target database administrators.

## Security Notes

Hosting private-key material is never accepted by the module; signing always uses an OCI KMS asymmetric key.

`resource_scopes` are incoming resource-server scopes for the hosting application. They are not downstream scopes requested from target tools.

`allowed_scopes` are the OAuth client scopes authorized on the Identity Domain app. Pass Identity Domain FQS strings directly.

Downstream target-tool authorization is optionally controlled by security policy in the Token Factory authorization policy secret.
