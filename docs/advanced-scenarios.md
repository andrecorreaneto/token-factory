## Advanced Scenarios

Most deployments should use `TokenFactory(oauth_apps=...)`. Use resolver and provider classes directly only for tests, local troubleshooting, or deployment systems that need custom loading behavior.

### `OAuthClientInfo` fields

Use these fields when constructing `oauth_apps` entries or when using `StaticOAuthClientResolver`, `VaultOAuthClientResolver`, or `LocalOAuthClientResolver` directly.

| Field | Required | Purpose |
| --- | --- | --- |
| `client_credentials` | yes, unless `client_credentials_secret_ocid` is set | Direct `client_id:client_secret`. |
| `client_credentials_secret_ocid` | yes, unless `client_credentials` is set | Vault secret containing `client_id:client_secret`. |
| `issuer` | yes | JWT `iss` used when signing assertions for this hosting app. |
| `private_key_pem` | one key source required | Direct private key PEM. |
| `private_key_path` | one key source required | Local private key path. |
| `private_key_secret_ocid` | one key source required | Vault secret containing private key PEM. |
| `private_key_passphrase` | optional | Direct private-key passphrase. |
| `private_key_passphrase_secret_ocid` | optional | Vault secret containing the passphrase. |
| `certificate_pem` | optional in resolver, required by Identity Domain setup | Direct certificate PEM matching the private key. |
| `certificate_path` | optional | Local certificate path. |
| `certificate_secret_ocid` | optional | Vault secret containing certificate PEM. |
| `kid` | strongly recommended | JWT `kid` header and Identity Domain certificate alias. |
| `resource_audiences` | yes for real caller-token validation | Accepted incoming caller assertion audiences for this hosting app. |
| `required_incoming_scopes` | optional | Required scopes that must already be present in the incoming caller assertion. Bootstrap derives this from Terraform `oauth_apps[*].resource_scopes`. |

### `VaultOAuthClientResolver`

This is the lower-level form of the preferred Vault-backed example. TokenFactory can still read Vault secrets through `runtime_config`, so a custom secret reader is optional.

```python
from token_factory import (
    OAuthClientInfo,
    TokenFactory,
    TokenFactoryRuntimeConfig,
    VaultOAuthClientResolver,
)

runtime_config = TokenFactoryRuntimeConfig(
    domain_url="https://<domain>.identity.oraclecloud.com:443",
    domain_region="us-chicago-1",
    timeout_seconds=30,
    oci_auth_mode="instance-principal",
    oci_region="us-chicago-1",
    subject_claim="sub",
    groups_claim="groups",
    authz_policy_enable=True,
    authz_policy_secret_ocid="ocid1.vaultsecret.oc1..<authz-policy-secret>",
    authz_policy_signature_mode="off",
)

oauth_client_resolver = VaultOAuthClientResolver(
    client_info={
        "orders-api": OAuthClientInfo(
            client_credentials_secret_ocid="ocid1.vaultsecret.oc1..<orders-client-credentials>",
            issuer="https://orders-api.example.com/token-factory",
            private_key_secret_ocid="ocid1.vaultsecret.oc1..<orders-private-key>",
            certificate_secret_ocid="ocid1.vaultsecret.oc1..<orders-certificate>",
            kid="orders-api-token-factory-cert",
            resource_audiences=["orders-api"],
            required_incoming_scopes=["orders-api.invoke"],
        )
    },
    runtime_config=runtime_config,
)

factory = TokenFactory(
    runtime_config=runtime_config,
    oauth_client_resolver=oauth_client_resolver,
)

result = factory.get_token(
    "<incoming-caller-access-token>",
    token_type="oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)
```

### Local-only `oauth_apps` Example

Use direct `oauth_apps` values for development or local troubleshooting when app material is already available outside OCI Vault.

```python
factory = TokenFactory(
    oauth_apps={
        "orders-api": {
            "client_credentials": "client-id:client-secret",
            "issuer": "https://orders-api.example.com/token-factory",
            "private_key_path": "/home/opc/.oci/orders-api-token-factory-private-key.pem",
            "certificate_path": "/home/opc/.oci/orders-api-token-factory-cert.pem",
            "kid": "orders-api-token-factory-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        }
    }
)
```

### `StaticOAuthClientResolver`

Use this when app material is already available as direct values in process memory. This is useful for tests, local integration scripts, or controlled deployment systems that inject secrets outside OCI Vault.

The `runtime_config` object below can also be supplied through process-wide shared runtime `TOKEN_FACTORY_*` variables. In that case, replace the explicit constructor with `TokenFactoryRuntimeConfig.from_env()`.

```python
from token_factory import (
    OAuthClientInfo,
    StaticAuthorizationPolicyProvider,
    StaticOAuthClientResolver,
    TokenFactory,
    TokenFactoryRuntimeConfig,
)

runtime_config = TokenFactoryRuntimeConfig(
    domain_url="https://<domain>.identity.oraclecloud.com:443",
    domain_region="us-chicago-1",
    timeout_seconds=30,
    oci_auth_mode="instance-principal",
    oci_region="us-chicago-1",
    subject_claim="sub",
    groups_claim="groups",
)

oauth_client_resolver = StaticOAuthClientResolver(
    {
        "orders-api": OAuthClientInfo(
            client_credentials="orders-client-id:orders-client-secret",
            issuer="https://orders-api.example.com/token-factory",
            private_key_pem="""-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----""",
            certificate_pem="""-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----""",
            kid="orders-api-token-factory-cert",
            resource_audiences=["orders-api"],
            required_incoming_scopes=["orders-api.invoke"],
        )
    }
)

authorization_policy_provider = StaticAuthorizationPolicyProvider.from_dict(
    {
        "version": 1,
        "grants": {
            "oauth": {
                "orders-readers": ["urn:opc:idm:orders.read"],
            },
            "oracle-database": {
                "db-users": ["urn:oracle:db::id::*"],
            },
        },
    }
)

factory = TokenFactory(
    runtime_config=runtime_config,
    oauth_client_resolver=oauth_client_resolver,
    authorization_policy_provider=authorization_policy_provider,
)

result = factory.get_token(
    "<incoming-caller-access-token>",
    token_type="oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)

oauth_access_token = result["token"]
```

### `LocalOAuthClientResolver`

Use this for local development where you want direct local OAuth app material. Caller assertion validation still uses TokenFactory's built-in hybrid validation against the configured Identity Domain.

The `runtime_config` object below can also be supplied through process-wide shared runtime `TOKEN_FACTORY_*` variables. In that case, replace the explicit constructor with `TokenFactoryRuntimeConfig.from_env()`.

```python
from token_factory import (
    LocalOAuthClientResolver,
    OAuthClientInfo,
    StaticAuthorizationPolicyProvider,
    TokenFactory,
    TokenFactoryRuntimeConfig,
)

runtime_config = TokenFactoryRuntimeConfig(
    domain_url="https://<domain>.identity.oraclecloud.com:443",
    domain_region="us-chicago-1",
    timeout_seconds=30,
    oci_auth_mode="oci-profile",
    oci_auth_profile="DEFAULT",
    oci_region="us-chicago-1",
    subject_claim="sub",
    groups_claim="groups",
)

oauth_client_resolver = LocalOAuthClientResolver(
    {
        "orders-api": OAuthClientInfo(
            client_credentials="local-client-id:local-client-secret",
            issuer="https://orders-api.example.com/token-factory",
            private_key_path="/home/opc/.oci/orders-api-token-factory-private-key.pem",
            certificate_path="/home/opc/.oci/orders-api-token-factory-cert.pem",
            kid="orders-api-token-factory-cert",
            resource_audiences=["orders-api"],
            required_incoming_scopes=["orders-api.invoke"],
        )
    }
)

authorization_policy_provider = StaticAuthorizationPolicyProvider.from_dict(
    {
        "version": 1,
        "grants": {
            "oauth": {
                "orders-readers": ["urn:opc:idm:orders.read"],
            },
        },
    }
)

factory = TokenFactory(
    runtime_config=runtime_config,
    oauth_client_resolver=oauth_client_resolver,
    authorization_policy_provider=authorization_policy_provider,
)

result = factory.get_token(
    "<incoming-caller-access-token>",
    "oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)

oauth_access_token = result["token"]
```

### Other Flow Calls

Once the factory is built with any resolver above, use the same call pattern for other token types:

```python
user_id_result = factory.get_token(
    "<incoming-caller-access-token>",
    token_type="userid",
    client_key="orders-api",
)

db_token, session_private_key_pem, expires_in, token_type, issued_token_type = factory.get_token(
    "<incoming-caller-access-token>",
    token_type="oracle-database",
    scope="urn:oracle:db::id::*",
    client_key="orders-api",
)
```

Use `get_token_with_oci_credential()` only for OCI-authenticated OAuth token exchange. It does not validate an end-user assertion and does not run group/scope authorization in current code.

```python
credential = {
    "tenancy": "ocid1.tenancy.oc1..<tenancy>",
    "user": "ocid1.user.oc1..<user>",
    "fingerprint": "aa:bb:cc:dd",
    "region": "us-chicago-1",
    "private_key_content": "<pem-private-key>",
}

oci_credential_result = factory.get_token_with_oci_credential(
    credential,
    scope="urn:opc:idm:__myscope__",
)

oauth_access_token = oci_credential_result["token"]
```
