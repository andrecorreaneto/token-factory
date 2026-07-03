# Token Factory Bootstrap

Terraform bootstrap for the infrastructure Token Factory needs when it is embedded in one or more hosting applications.

Token Factory is not the OAuth client. Each hosting application is both:

- the OAuth confidential client used for outbound token exchange, introspection authentication, and UPST-backed flows;
- the resource-server boundary for incoming end-user access tokens.

This module provisions shared Token Factory storage/config plus any number of hosting application OAuth app configurations from one state file.

## Mental Model

```text
shared Token Factory config + N oauth_apps entries = Token Factory bootstrap
```

Shared resources are created once:

- optional shared OCI Vault;
- optional shared Vault master key;
- authorization policy runtime config;
- common Identity Domain/runtime environment values.

OAuth app/runtime resources are created once per `oauth_apps` entry:

- Identity Domain confidential OAuth app with OAuth introspection enabled;
- configured Identity Domain application-role grants;
- OAuth partner certificate;
- optional IdentityPropagationTrust;
- runtime IAM principal wrapper;
- runtime Vault read policy;
- OAuth client credentials/private key/certificate secrets.

Adding a new hosting application later should be an additive change: add one `oauth_apps` entry and apply.

## Example

```hcl
module "token_factory_bootstrap" {
  source = "../token-factory-bootstrap"

  tenancy_ocid           = var.tenancy_ocid
  region                 = "us-ashburn-1"
  identity_domain_url    = "https://idcs-example.identity.oraclecloud.com"
  identity_domain_region = "us-ashburn-1"
  resource_name_prefix   = "token-factory"

  enable_oci_secrets                     = true
  oci_secrets_compartment_ocid           = "ocid1.compartment.oc1..secrets"
  oci_vault_existing_ocid                = "ocid1.vault.oc1.iad..."
  oci_master_key_existing_ocid           = "ocid1.key.oc1.iad..."
  restrict_secret_policy_to_secret_ocids = true

  token_factory_authz_policy_secret_ocid    = "ocid1.vaultsecret.oc1.iad...authz"
  token_factory_authz_policy_signature_mode = "on"
  token_factory_authz_policy_environment    = "dev"
  token_factory_authz_policy_trusted_signers = [
    {
      key_id         = "ocid1.key.oc1.iad..."
      key_version_id = "ocid1.keyversion.oc1.iad..."
      algorithm      = "SHA_256_RSA_PKCS_PSS"
      public_key_pem = <<EOT
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
EOT
    }
  ]

  oauth_apps = {
    MCP_SERVER = {
      display_name       = "mcp-server-token-factory-client"
      description        = "OAuth client and resource-server config for MCP server."
      issuer             = "https://mcp-server.example.com/token-factory"
      kid                = "mcp-server-token-factory-cert"
      resource_audiences = ["mcp-server"]
      resource_scopes    = ["invoke"]
      allowed_scopes     = []
      app_roles          = []

      runtime = {
        principal_type   = "compute-instance"
        compartment_ocid = "ocid1.compartment.oc1..runtime"
        resource_ocid    = "ocid1.instance.oc1.iad..."
        oci_auth_profile = null
        oci_region       = null
      }

      enable_identity_propagation_trust = true
      propagation_trust_claim_name      = "upstclient"
      propagation_trust_claim_value     = "tokenexchange"

      jwt_key_material_source = "generate"

      jwt_private_key_pem                     = null
      jwt_private_key_passphrase              = null
      jwt_certificate_pem                     = null
      jwt_certificate_pem_for_identity_domain = null

      private_key_secret_existing_ocid            = null
      private_key_passphrase_secret_existing_ocid = null
      certificate_secret_existing_ocid            = null
    }
  }
}
```

## Important Inputs

### Shared Inputs

| Input | Default | Description |
|---|---:|---|
| `tenancy_ocid` | required | OCI tenancy OCID. |
| `region` | `null` | OCI provider region. Defaults to `identity_domain_region`. |
| `resource_name_prefix` | `"token-factory"` | Prefix for shared Token Factory resources only. `null` or `""` falls back to `"token-factory"`. |
| `identity_domain_url` | required | Identity Domain base URL. |
| `identity_domain_region` | required | Identity Domain/OCI region. |
| `enable_oci_secrets` | `true` | Store OAuth app material in OCI Vault. |
| `oci_secrets_compartment_ocid` | `null` | Compartment for Vault secrets and runtime secret-read policies. |
| `oci_vault_existing_ocid` | `null` | Existing Vault OCID. If omitted and secrets are enabled, the module creates `oci_kms_vault.this`. |
| `oci_master_key_existing_ocid` | `null` | Existing key OCID. If omitted and secrets are enabled, the module creates `oci_kms_key.this`. |
| `restrict_secret_policy_to_secret_ocids` | `false` | Restrict each runtime policy to exact secret OCIDs. |

### Runtime Config Inputs

| Input | Default | Runtime output |
|---|---:|---|
| `token_factory_timeout_seconds` | `30` | `TOKEN_FACTORY_TIMEOUT_SECONDS` |
| `token_factory_subject_claim` | `"sub"` | `TOKEN_FACTORY_SUBJECT_CLAIM` |
| `token_factory_groups_claim` | `"groups"` | `TOKEN_FACTORY_GROUPS_CLAIM` |
| `token_factory_log_full_assertion` | `false` | `TOKEN_FACTORY_LOG_FULL_ASSERTION`, only when true |
| `token_factory_authz_policy_secret_ocid` | `null` | `TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID` |
| `token_factory_authz_policy_signature_mode` | `"off"` | `TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE` |
| `token_factory_authz_policy_trusted_signers` | `[]` | `TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON` |
| `token_factory_authz_policy_environment` | `null` | `TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT` |
| `emit_authz_policy_tenant_id` | `false` | `TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID = tenancy_ocid`, only when true |

`token_factory_authz_policy_trusted_signers` entries must have this shape:

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

`oauth_apps` is a map. Each entry represents one hosting application's Identity Domain OAuth confidential app plus the runtime/IAM/secret configuration Token Factory needs to use that app. The map key is the canonical Token Factory `CallerContext.client_key` and must be uppercase.

The module emits `oauth_app_configs` in the Python `OAuthClientInfo` shape for Vault-backed deployments, keyed by the same `CallerContext.client_key`. Inline/raw credential deployments use the sensitive `oauth_app_sensitive_configs` outputs.

| Field | Description |
|---|---|
| `resource_name_prefix` | Optional prefix for this OAuth app's resources. Defaults to the normalized map key, for example `MCP_SERVER` becomes `mcp-server`. |
| `display_name` | Identity Domain confidential app display name. |
| `description` | Identity Domain confidential app description. |
| `issuer` | JWT assertion issuer for this OAuth app/client identity. |
| `kid` | JWT key ID and OAuth partner certificate alias. |
| `resource_audiences` | Accepted incoming token audiences for this hosting app/resource server. |
| `resource_scopes` | Required incoming Identity Domain resource-server scopes. Non-empty values make the Identity Domain app an OAuth resource. The output maps this to Token Factory `required_incoming_scopes`. |
| `allowed_scopes` | OAuth client authorized scopes for the Identity Domain app. Defaults to `[]`. Values must be Identity Domain FQS strings. |
| `app_roles` | Identity Domain app-role grants for the OAuth app. Defaults to `[]`. |
| `runtime.principal_type` | `compute-instance`, `oci-function`, `oke-cluster`, or `user-group`. |
| `runtime.compartment_ocid` | Compartment for dynamic group matching or group/policy placement. |
| `runtime.resource_ocid` | Optional exact compute/function/cluster OCID. |
| `runtime.oci_auth_profile` | Used only when `principal_type = "user-group"`; defaults to `DEFAULT` in runtime config. |
| `runtime.oci_region` | Per-runtime `TOKEN_FACTORY_OCI_REGION`; falls back to `oci_secrets_region` or `identity_domain_region`. |
| `enable_identity_propagation_trust` | Create IdentityPropagationTrust for `oracle-database` and `oci-service` UPST flows. |
| `propagation_trust_claim_name` / `propagation_trust_claim_value` | Optional trust client claim pair. |
| `jwt_key_material_source` | `generate`, `provided_pem`, or `existing_secret_ocids`. |
| `jwt_private_key_pem` / `jwt_certificate_pem` | Required when `jwt_key_material_source = "provided_pem"`. |
| `jwt_certificate_pem_for_identity_domain` | Required when `jwt_key_material_source = "existing_secret_ocids"`. |
| `private_key_secret_existing_ocid` / `certificate_secret_existing_ocid` | Required when `jwt_key_material_source = "existing_secret_ocids"`. |
| `private_key_passphrase_secret_existing_ocid` | Optional existing passphrase secret. |

Supported `app_roles` values are `Me`, `Approval Workflow Administrator`, `Identity Domain Administrator`, `Reset Password`, `User Manager`, `User Administrator`, `Kerberos Administrator`, `Verify Email`, `Change Password`, `Posix Viewer`, `DB Administrator`, `Me Password Validator`, `Digitalid Wallet`, `Digitalid Verifier`, `Digitalid Issuer`, `Digitalid Admin`, `Help Desk Administrator`, `Audit Administrator`, `MFA Client`, `Security Administrator`, `Authenticator Client`, `Self Registration`, `Cloud Gate`, `Forgot Password`, `Signin`, and `Application Administrator`.

Derived runtime auth mode:

| `runtime.principal_type` | `TOKEN_FACTORY_OCI_AUTH_MODE` |
|---|---|
| `compute-instance` | `instance-principal` |
| `oci-function` | `resource-principal` |
| `oke-cluster` | `resource-principal` |
| `user-group` | `oci-profile` |

## Outputs

| Output | Description |
|---|---|
| `token_factory_shared_runtime_config` | Shared runtime config base. Excludes OAuth app identity fields and per-runtime OCI auth values. |
| `token_factory_runtime_configs` | Full runtime config map by OAuth app key. |
| `token_factory_runtime_config_env` | Shell `export` lines by OAuth app key. |
| `oauth_app_configs` | Token Factory `OAuthClientInfo`-shaped resolver config by OAuth app key. Regular output contains only non-secret values and secret OCID references. |
| `oauth_app_configs_json` | JSON-encoded resolver config for Vault-backed application deployment. Regular output contains only non-secret values and secret OCID references. |
| `oauth_app_sensitive_configs` | Sensitive `OAuthClientInfo`-shaped resolver config including inline credentials and PEM values when `enable_oci_secrets = false`. |
| `oauth_app_sensitive_configs_json` | Sensitive JSON-encoded resolver config including inline credentials and PEM values when `enable_oci_secrets = false`. |
| `oauth_app_runtime_secret_ocids` | OAuth material secret OCIDs each OAuth app runtime must read. |
| `runtime_secret_ocids` | Authz policy secret plus OAuth app secret OCIDs by OAuth app key. |
| `runtime_principals` | Runtime IAM principal details by OAuth app key. |
| `secret_policy_statements` | Generated Vault read policy statements by OAuth app key. |
| `oauth_app_resource_ids` | App, app-role grant, cert, trust, IAM, and secret IDs by OAuth app key. |
| `provisioned_resource_ids` | Combined shared and OAuth app/runtime resource IDs. |
| `provisioned_resources` | Shared and OAuth app/runtime resources with names and OCIDs for lookup. |

Regular outputs intentionally avoid inline credentials and PEM values. The inline/raw resolver outputs are explicitly marked sensitive.

## Runtime Use On OCI Compute

After apply, export the runtime config for the OAuth app key that runs on the compute instance:

```powershell
terraform output -raw token_factory_runtime_config_env
```

For a map output, select the relevant key:

```powershell
terraform output -json token_factory_runtime_config_env
```

For the normal Vault-backed path, save `oauth_app_configs_json` into application config. The application loads it into Token Factory's resolver:

```python
import json
from token_factory import OAuthClientInfo, TokenFactory, VaultOAuthClientResolver

with open("oauth_app_configs.json", "r", encoding="utf-8") as handle:
    raw_config = json.load(handle)

client_info = {
    client_key: OAuthClientInfo(**config)
    for client_key, config in raw_config.items()
}

factory = TokenFactory(
    oauth_client_resolver=VaultOAuthClientResolver(client_info=client_info),
)
```

For local/dev deployments with `enable_oci_secrets = false`, use `oauth_app_sensitive_configs_json` instead. Terraform will redact that output by default; retrieve it intentionally with:

```powershell
terraform output -raw oauth_app_sensitive_configs_json
```

The app should pass the matching `CallerContext.client_key` when calling Token Factory:

```python
from token_factory import CallerContext

result = factory.get_token(
    credential=end_user_access_token,
    target_tool="oauth",
    scope="urn:opc:idm:example.read",
    caller_context=CallerContext(client_key="mcp_server"),
)
```

## Resource Naming

Singleton shared resources use `this`:

- `oci_kms_vault.this`
- `oci_kms_key.this`

Shared resource names use the top-level `resource_name_prefix`, defaulting to `token-factory`:

- `token-factory-vault`
- `token-factory-master-key`

Per-app resource names use `oauth_apps[*].resource_name_prefix`, defaulting to the normalized `oauth_apps` map key:

- `mcp-server-client`
- `mcp-server-identity-propagation-trust`
- `mcp-server-runtime-dynamic-group`
- `mcp-server-secrets-policy`

Keyed OAuth app/runtime resources use `these`:

- `oci_identity_dynamic_group.these`
- `oci_identity_group.these`
- `oci_identity_policy.these`
- `oci_identity_domains_app.these`
- `oci_identity_domains_grant.these`
- `oci_identity_domains_oauth_partner_certificate.these`
- `oci_identity_domains_identity_propagation_trust.these`
- `tls_private_key.these`
- `tls_self_signed_cert.these`

Grouped OAuth material secrets use descriptive plural names:

- `oci_vault_secret.client_credentials`
- `oci_vault_secret.private_keys`
- `oci_vault_secret.private_key_passphrases`
- `oci_vault_secret.certificates`

## Notes

- Generated and provided private key material is stored in Terraform state. Use `existing_secret_ocids` when Terraform should not handle raw private key material.
- `resource_scopes` are incoming resource-server scopes for the hosting application, not downstream scopes requested from target tools.
- `allowed_scopes` are the OAuth client scopes authorized on the Identity Domain app. Pass Identity Domain FQS strings directly.
- `app_roles = []` disables Identity Domain app-role grants for that OAuth app.
- Downstream target-tool authorization is controlled by the Token Factory authorization policy secret.
- The legacy `client/` folder predates this super-module shape. Prefer the root module documented here for new infrastructure.


