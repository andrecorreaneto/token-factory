# Token Factory

`TokenFactory` is a small client library that converts an incoming caller credential into the exact credential format a downstream target needs. Instead of making every client implement its own JWT assertion signing, Identity Domain token exchange, UPST handling, Vault secret retrieval, and OCI signer setup, this module provides focused entry points through `TokenFactory.get_token()` and `TokenFactory.get_token_with_oci_credential()`.

This is important because the supported targets do not all consume the same kind of credential. Some consumers need an OAuth access token, some need a user identifier, some need an OCI `TokenExchangeSigner`, and Oracle Database flows need a scoped database token plus the matching session key material. `TokenFactory` centralizes those translations so that clients can stay small, reuse the same security configuration, and avoid duplicating fragile trust, certificate, and secret-management logic across multiple services or scripts.

TokenFactory exposes two credential-exchange APIs. Use `get_token()` when you have an incoming caller assertion. Use `get_token_with_oci_credential()` when you have an OCI signer dictionary or OCI CLI profile and need an OAuth access token.

Most deployments embed TokenFactory in one running component, such as an agent or MCP server, and configure one hosting OAuth app for that process. Use the same structured shape for every deployment: pass an `oauth_apps` map to `TokenFactory(...)` and pass `client_key` to `get_token(...)`. A single-client process is just an `oauth_apps` map with one entry.

## get_token API

The main client entry point is:

```python
factory = TokenFactory(oauth_apps=oauth_apps)
result = factory.get_token(
    credential,
    token_type,
    scope=None,
    client_key="orders-api",
)
```

`TokenFactory(oauth_apps=...)` loads the process runtime configuration and configured hosting OAuth apps once, and `get_token()` performs the assertion-backed exchange for the requested downstream target. Always pass `client_key=...` so TokenFactory selects the correct hosting app OAuth identity and resource-server validation settings.

Credentials that refer to OCI signer dictionaries and OCI CLI profile names do not flow through `get_token()`. They should use `get_token_with_oci_credential()` instead.

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `credential` | yes | Incoming caller assertion string, usually an Identity Domain access token for the hosting application. |
| `token_type` | yes | The requested output type. Supported values are `oracle-database`, `oci-service`, `oauth`, and `userid`. |
| `scope` | depends on flow | Required for `oauth` and `oracle-database`. Not used for `userid` or `oci-service`. |
| `client_key` | yes | Key into the configured `oauth_apps` map. Required even when the map has one entry. |

### Accepted `credential` shapes

| Credential shape | Supported flows | Notes |
| --- | --- | --- |
| Incoming assertion string | `oauth`, `userid`, `oracle-database`, `oci-service` | TokenFactory validates this assertion before trusting `sub`, groups, audience, or incoming scopes. |

### Return value

`get_token()` returns different result types depending on `token_type`:

- `oracle-database`: a tuple containing `(token, private_key_pem, expires_in, token_type, issued_token_type)`; the token and private key are always the first two elements
- `oci-service`: an OCI `TokenExchangeSigner`
- `oauth`: a dictionary containing `token`, `expires_in`, `token_type`, and `issued_token_type`
- `userid`: a dictionary containing `user_id` and `issued_token_type`

### Supported Flows

Once you know the downstream consumer, selecting a flow is straightforward:

- Choose `oracle-database` when the caller needs a scoped Oracle Database token and the matching session private key material.
- Choose `oci-service` when the caller needs an OCI SDK signer rather than a bearer token string.
- Choose `oauth` when the downstream system expects a regular OAuth access token.
- Choose `userid` when the caller only needs the resolved subject identifier and does not need to keep the exchanged token.

The table below is a quick handout for clients integrating with the library. It shows what input each flow expects, what comes back, and which external trust or OCI components are involved.

| `token_type` | Accepted credential types | Extra input | Returned token or value | Main upstream dependencies |
| --- | --- | --- | --- | --- |
| `oracle-database` | incoming caller assertion string | downstream `scope` required | Oracle Database scoped access token plus session private key as the first two tuple elements | Incoming token validation, optional group-scope authorization, JWT assertion signing, IdentityPropagationTrust, `TokenExchangeSigner`, Identity Data Plane `generate_scoped_access_token` |
| `oci-service` | incoming caller assertion string | no scope | OCI `TokenExchangeSigner` backed by a UPST, not a raw token string | Incoming token validation, JWT assertion signing, IdentityPropagationTrust, `TokenExchangeSigner` |
| `oauth` | incoming caller assertion string | downstream `scope` required | OAuth access token in the response payload (`issued_token_type=oauth`) | Incoming token validation, optional group-scope authorization, Identity Domain `/oauth2/v1/token` JWT bearer grant |
| `userid` | incoming caller assertion string | no scope | extracted `user_id` from the validated incoming assertion (`issued_token_type=userid`) | Incoming token validation only |

### Validation and common errors

- Unsupported `token_type` values raise `ValueError`.
- `oauth` and `oracle-database` raise `ValueError` if `scope` is missing.
- All `get_token()` token types raise `ValueError` if `credential` is not a non-empty caller assertion string.
- `CallerAssertionValidationError` maps to invalid incoming caller assertions.
- `AuthorizationError` maps to group-scope authorization denial when authorization policy enforcement is enabled.
- Configuration issues raise `ConfigurationError`.
- Upstream exchange or decode failures raise `TokenExchangeError`.

## get_token_with_oci_credential API

Use `get_token_with_oci_credential()` only for OCI-authenticated OAuth token exchange. This API is separate from `get_token()` because it authenticates with OCI signer material instead of validating an incoming caller assertion.

```python
factory = TokenFactory()
result = factory.get_token_with_oci_credential(
    credential,
    scope="urn:opc:idm:orders.read",
)
```

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `credential` | yes | OCI signer dictionary or OCI CLI profile name. |
| `scope` | no | OAuth scope to request from the Identity Domain token endpoint. |

### Accepted `credential` shapes

| Credential shape | Supported flow | Notes |
| --- | --- | --- |
| OCI signer dictionary | OAuth token exchange | Must include `tenancy`, `user`, `fingerprint`, `region`, and exactly one of `private_key_file`/`private_key_file_location` or `private_key_content`. |
| OCI CLI profile name | OAuth token exchange | Loaded from `~/.oci/config`, using the profile name string passed as `credential`. |

### Return value

`get_token_with_oci_credential()` returns an OAuth result dictionary containing `token`, `expires_in`, `token_type`, and `issued_token_type`.

### Validation and common errors

- Invalid OCI signer dictionaries raise `ValueError`.
- Missing OCI CLI profiles or malformed OCI config files raise `ValueError`.
- Upstream OAuth exchange failures raise `TokenExchangeError`.
- This API does not validate an end-user assertion, does not use `client_key`, and does not run group-scope authorization.


## How TokenFactory Works

TokenFactory is essentially a helper library that hides the complexity of token exchange on behalf of its importing clients. As such, before requesting a token, it validates the requesting credential. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`, it also checks whether the subject in the credential is entitled to request the scope for `oauth` and `oracle-database` flows.

### Credential Validation

1. A client passes an incoming caller access token to `TokenFactory.get_token(...)`, along with the requested `token_type`, an optional downstream `scope`, and the required `client_key`.
2. TokenFactory uses `client_key` to select the hosting application's OAuth app config, including client credentials, JWT signing material, resource audiences, and required incoming scopes.
3. TokenFactory introspects the incoming caller token at the Identity Domain `/oauth2/v1/introspect` endpoint, authenticating with the resolved hosting app OAuth client.
4. The introspection response must return `active=true`. If the token is inactive, unrecognized, expired, or otherwise invalid, TokenFactory fails closed.
5. TokenFactory checks the introspection result against the resolved resource-server config: `aud` must match `resource_audiences`, and the incoming token scopes must include `required_incoming_scopes` when configured.
6. TokenFactory discovers Identity Domain signing metadata from `<domain_url>/.well-known/openid-configuration`, reads the discovered issuer and JWKS URI, and validates the same incoming JWT signature and registered claims.
7. TokenFactory starts with the introspection claims, then overlays only the configured `groups_claim` from the validated JWT. This lets authorization use custom signed claims that introspection does not return.
8. TokenFactory extracts the caller subject from `subject_claim` and caller groups from `groups_claim`.

### Token Request Authorization

1. Authorization policy enforcement is opt-in. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=false` or unset, TokenFactory skips group-scope authorization checks for scoped flows.
2. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`, scoped flows such as `oauth` and `oracle-database` check the authorization policy to determine whether the requesting credential is entitled to request the scope.
3. When enforcement is enabled, at least one caller group must be allowed to request every downstream scope. If no policy provider is configured or the policy does not grant the scope, TokenFactory fails closed.
4. For `oauth`, authorization policy entries must match the requested scope exactly. If the request uses a fully qualified resource scope such as `https://orders-api.example.com/orders.read`, the policy must grant that fully qualified value.
5. Unscoped flows such as `userid` and `oci-service` do not run group-scope authorization.

### Token Request

1. TokenFactory signs a new JWT assertion using the resolved hosting app issuer, private key, and `kid` when the selected flow needs assertion-backed token exchange.
2. For `oauth`, TokenFactory first returns the incoming token unchanged when it is already valid for the requested OAuth resource audience and already carries the issued scope. Otherwise, it exchanges the assertion at the Identity Domain token endpoint and returns a downstream OAuth access token payload.
3. For `oracle-database`, TokenFactory builds a UPST-backed signer, requests a scoped database token, and returns the database token plus session private key material.
4. For `oci-service`, TokenFactory returns an OCI `TokenExchangeSigner` backed by the propagated user security token.
5. For `userid`, TokenFactory returns the trusted subject identifier after credential validation.
6. The client receives the token-type-specific result without implementing introspection, JWT signature validation, Vault secret loading, assertion signing, IdentityPropagationTrust, authorization, or OCI token exchange logic itself.

## Required Runtime Configuration

TokenFactory uses one configuration style for assertion-backed flows:

- **Single-client process**: one running component owns one TokenFactory instance and one hosting OAuth app. Pass `oauth_apps` with one entry to `TokenFactory(oauth_apps=...)`, and pass that entry's key as `client_key` on every `get_token(...)` call.
- **Multi-client process**: one running process hosts multiple OAuth app identities. Pass `oauth_apps` with one entry per hosting OAuth app, and pass `client_key` on every `get_token(...)` call to select the intended app.

Shared runtime configuration covers process-wide settings such as Identity Domain URL, OCI auth mode, timeout, subject/group claim names, and authorization-policy verification. OAuth app configuration describes the hosting component's Identity Domain OAuth client credentials, JWT signing material, resource-server audiences, and required incoming scopes.

Production environments should store OAuth app credentials, private keys, certificates, and signed authorization policy documents in OCI Vault. Direct values and local files are intended for development, tests, and controlled troubleshooting.

When Vault-backed values are used, an IAM policy for the principal that runs the hosting application is required. The policy must allow reading every Vault secret OCID referenced by the selected OAuth app plus the authorization policy secret when one is configured.

### Terraform Bootstrap Module

Use [../token-factory-bootstrap/README.md](Token Factory Bootstrap Module) to provision required infrastructure for Token Factory runtime.

The [../token-factory-bootstrap/client](Bootstrap client wrapper) exposes a concise output surface that application teams can plug into their runtime environments:

| Output | Use |
| --- | --- |
| `runtime_config_env` | Shared shell `export` lines for runtime config, for deployments configured through process environment variables. |
| `runtime_config` | Shared constructor-shaped config for structured deployments. Pass it directly as `TokenFactory(runtime_config=runtime_config, oauth_apps=oauth_apps)`, or export `runtime_config_env` and omit it. |
| `oauth_apps` | Required structured OAuth app config for TokenFactory assertion-backed flows. Use one entry for single-client processes and multiple entries for multi-client processes. |
| `provisioned_resources` | Convenience lookup output with names and OCIDs for shared resources, OAuth apps, certificates, trusts, runtime principals, policies, and secrets. Null unless the client module sets `output_provisioned_resources = true`. |

The following pre-requisites are fulfilled by the bootstrap module. They are presented here for awareness.

#### Identity Domain Pre-requisites

**1. Confidential OAuth app client for each hosting app**

Create one confidential app client in the same Identity Domain used by `TOKEN_FACTORY_DOMAIN_URL` for each hosting application that embeds TokenFactory.

TokenFactory itself is not the OAuth client. The selected hosting app OAuth client is used for token introspection, JWT bearer exchange, and UPST-backed exchange. This material comes from the selected `oauth_apps[client_key]` entry or from an explicitly supplied resolver.

Required grant types:

- enable `Client Credentials`
- enable `JWT Assertion`

Operational notes:

- The Vault secret value must be exactly `client_id:client_secret`.
- For incoming caller assertion validation, configure the app as a resource server and issue caller tokens with an audience that appears in `OAuthClientInfo.resource_audiences`.
- If `OAuthClientInfo.required_incoming_scopes` is set, the incoming caller assertion must already contain those scopes in `scope` or `scp`.
- For UPST-backed flows (`oracle-database`, `oci-service`), the selected app client ID must also be listed in the `oauthClients` array of the `IdentityPropagationTrust`.
- If the Identity Domain token endpoint starts returning `400 invalid_scope`, verify that the selected OAuth app owns the requested resource scope and that the caller application is allowed to request it. For resource scopes, the request often uses the fully qualified form such as `https://playground.mcp.server/tools.get_user_info`, while the issued access token may contain only `tools.get_user_info`.
- If the Identity Domain token endpoint starts returning `400 invalid_request` after scope changes, verify the selected OAuth app grants, certificate alias, and JWT assertion configuration.

**2. IdentityPropagationTrust for UPST (User Principal Service Token) Flows**

`oracle-database` and `oci-service` depend on an IdentityPropagationTrust because TokenFactory signs a JWT assertion for the selected hosting app and exchanges it into a UPST-backed signer.

The trust must be aligned with the module configuration:

- `issuer` must equal the selected `OAuthClientInfo.issuer`
- `publicCertificate` must represent the same certificate/private-key pair configured for the selected `OAuthClientInfo`
- `oauthClients` must include the selected hosting app OAuth client ID
- `subjectClaimName` should remain compatible with the module's JWT payload, which uses `sub`
- if your trust requires a client claim, model that claim as part of the selected OAuth app/runtime configuration

The common propagation-claim pattern is:

```text
TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM="upstclient:tokenexchange"
```

That maps cleanly to an IdentityPropagationTrust using:

- `clientClaimName: "upstclient"`
- `clientClaimValues: ["tokenexchange"]`

Treat this claim as OAuth-app trust material rather than a shared TokenFactory default.

Template request:

```sh
curl -X POST \
  -H 'Authorization: Bearer <admin-access-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "active": true,
    "allowImpersonation": false,
    "issuer": "https://upst.tokenfactory/",
    "name": "Token Trust JWT to UPST",
    "oauthClients": ["<hosting-oauth-client-id>"],
    "publicCertificate": "<base64-encoded-leaf-certificate>",
    "subjectClaimName": "sub",
    "subjectMappingAttribute": "userName",
    "subjectType": "User",
    "type": "JWT",
    "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
  }' \
  'https://<domain>.identity.oraclecloud.com:443/admin/v1/IdentityPropagationTrusts'
```

If your trust enforces a client claim, add:

```json
"clientClaimName": "upstclient",
"clientClaimValues": ["tokenexchange"]
```

The Terraform bootstrap module can provision this trust for each `oauth_apps` entry when `enable_identity_propagation_trust = true`.

**3. Identity Domain certificate store and `kid`**

For `oauth`, TokenFactory sends a JWT bearer assertion to the Identity Domain token endpoint. The intended production setup is:

- load the selected hosting app public key certificate into the Identity Domain certificate store
- set the certificate alias to exactly match `OAuthClientInfo.kid`
- configure the same certificate through the selected `OAuthClientInfo`
- configure the matching private key through the selected `OAuthClientInfo`

Why this matters:

- `factory.py` adds `{"kid": <selected kid>}` to the JWT header when a `kid` is set
- Identity Domain uses that alias to locate the certificate that validates the assertion signature
- each `oauth_apps` entry used for assertion-backed exchange needs a certificate source, and the external Identity Domain validation still depends on the certificate matching the signing key

If `kid` is omitted, TokenFactory sends an assertion without a `kid` header. An explicit `kid` is the clearer and more controlled setup.

#### OCI Vault secret requirements

The module can load OAuth app credentials, signing material, certificates, and authorization policy documents from OCI Vault.

Expected secret contents when Vault-backed sources are used through `oauth_apps` secret OCID fields:

- `client_credentials_secret_ocid`: plain text `client_id:client_secret`
- `private_key_secret_ocid`: PEM-encoded RSA private key
- `private_key_passphrase_secret_ocid`: plain text private-key passphrase
- `certificate_secret_ocid`: PEM-encoded X.509 certificate
- `TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID`: raw policy JSON or signed policy envelope JSON

Notes:

- Secret bundle content is base64-decoded and then treated as UTF-8 text, so PEM text is the safest format for key and certificate secrets.
- If `TOKEN_FACTORY_OCI_REGION` is not set, the secret's region is derived from the OCID.
- If any secret OCID source is configured, the runtime principal must be able to read every referenced secret. Use a dynamic group for instance-principal and resource-principal runtimes, or a user group for `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile`.
- Example dynamic-group matching rules:

  ```text
  # Instance principal: all compute instances in one compartment.
  instance.compartment.id = '<instance-compartment-ocid>'

  # Instance principal: one compute instance.
  instance.id = '<instance-ocid>'

  # Resource principal: all OKE clusters in one compartment.
  ALL {resource.type = 'cluster', resource.compartment.id = '<oke-cluster-compartment-ocid>'}

  # Resource principal: one OKE cluster.
  ALL {resource.id = '<oke-cluster-ocid>', resource.compartment.id = '<oke-cluster-compartment-ocid>'}
  ```

- Example policies granting Vault secret reads:

  ```text
  # Instance-principal authentication.
  allow dynamic-group <instance-dynamic-group> to read secret-bundles in compartment <secrets-compartment-name>

  # Resource-principal authentication, assuming the principal is an OKE cluster.
  allow dynamic-group <oke-cluster-dynamic-group> to read secret-bundles in compartment <secrets-compartment-name>

  # API-key authentication through TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile.
  allow group <user-group> to read secret-bundles in compartment <secrets-compartment-name>
  ```

  Add `where target.secret.id = '<secret-ocid>'` to restrict a policy to a specific configured secret.

- Factory-owned OCI SDK clients use Instance Principals by default. `TOKEN_FACTORY_OCI_AUTH_MODE=resource-principal` uses Resource Principals directly, and `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile` enables local OCI API-key profile fallback.
- Vault reads are skipped for any material supplied directly through `OAuthClientInfo`, such as `client_credentials`, `private_key_path`, `private_key_pem`, `certificate_path`, or `certificate_pem`.


### Shared runtime environment variables

These variables populate `TokenFactoryRuntimeConfig` or process-level TokenFactory defaults and apply to the running TokenFactory process, regardless of which OAuth app is selected for a call.

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOKEN_FACTORY_DOMAIN_URL` | yes | Identity Domain base URL, for example `https://<domain>.identity.oraclecloud.com:443`. Trailing slash is removed. |
| `TOKEN_FACTORY_DOMAIN_REGION` | yes | OCI region used for UPST `TokenExchangeSigner` and Identity Data Plane calls. |
| `TOKEN_FACTORY_TIMEOUT_SECONDS` | optional | HTTP timeout in seconds; default `30`. |
| `TOKEN_FACTORY_OCI_AUTH_MODE` | optional | OCI auth mode for factory-owned OCI SDK clients: `instance-principal` (default), `resource-principal`, or `oci-profile`. Required in practice when Vault OCIDs must be read. |
| `TOKEN_FACTORY_OCI_AUTH_PROFILE` | optional | OCI CLI profile used when `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile`; defaults to `DEFAULT`. |
| `TOKEN_FACTORY_OCI_REGION` | optional | Region override for OCI Vault secret reads. If unset, secret region is derived from the secret OCID when possible. |
| `TOKEN_FACTORY_SUBJECT_CLAIM` | optional | Claim name used to extract the validated caller subject; defaults to `sub`. |
| `TOKEN_FACTORY_GROUPS_CLAIM` | optional | Claim name used to extract caller groups for authorization; defaults to `groups`. |
| `TOKEN_FACTORY_LOG_FULL_ASSERTION` | optional | Enables full compact JWT logging. Use only for controlled troubleshooting because assertions are replay-sensitive. |
| `TOKEN_FACTORY_LOG_LEVEL` | optional | Module logger level; defaults to `INFO`. Accepted values are `CRITICAL`, `FATAL`, `ERROR`, `WARNING`, `WARN`, `INFO`, `DEBUG`, and `NOTSET`. |

### Authorization policy environment variables

Authorization policy enforcement is disabled by default. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=false` or unset, TokenFactory does not run group-scope authorization checks for scoped token requests. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`, scoped assertion-backed flows (`oauth` and `oracle-database`) require a configured policy provider and are denied after caller assertion validation if no policy is configured or no grant matches.

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE` | optional | Enables TokenFactory group-scope authorization when set to `1`, `true`, `yes`, `y`, or `on`; defaults to `false`. |
| `TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID` | required when enforcement uses the built-in Vault policy provider | OCI Vault secret OCID containing raw authorization policy JSON in `off` mode or a signed authorization policy envelope in `on` mode. This configures one policy-provider path; it is not the enforcement switch. |
| `TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE` | optional | `off` or `on`; defaults to `off`. Production deployments with the security-owned matrix should use `on`. |
| `TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON` | required when signature mode is `on` | JSON array of trusted signer entries with `key_id`, `key_version_id`, `algorithm`, and `public_key_pem`. |
| `TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT` | optional | Expected signed-policy `metadata.environment`, such as `prod`. If set, mismatches fail closed. |
| `TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID` | optional | Expected signed-policy `metadata.tenant_id`. Bootstrap emits this only when `emit_authz_policy_tenant_id = true`. |

Trusted signer entry shape:

```json
{
  "key_id": "ocid1.key.oc1...",
  "key_version_id": "ocid1.keyversion.oc1...",
  "algorithm": "SHA_256_RSA_PKCS_PSS",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

### `oauth_apps` configuration

Every assertion-backed `get_token(...)` call resolves the hosting OAuth app from the `oauth_apps` map passed to `TokenFactory(oauth_apps=...)`. The same structure is used for single-client and multi-client deployments.

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

Important behavior details:

- `get_token()` validates incoming caller assertions before trusting subject, groups, audience, or incoming scopes.
- `get_token()` authorizes scoped downstream flows only when `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`. In current code, scoped flows are `oauth` and `oracle-database`.
- For `oauth`, `scope` is the Identity Domain token request scope. Use the fully qualified resource scope when the Identity Domain requires it, for example `https://playground.mcp.server/tools.get_user_info`. TokenFactory authorizes the exact requested scope, so policy documents must grant that fully qualified value.
- For `oauth`, TokenFactory can pass through the incoming token instead of minting a new one only when the validated incoming token already has the requested resource audience and the issued scope.
- `userid` validates the incoming assertion and extracts the configured subject claim, but does not run group/scope authorization.
- `oci-service` validates the incoming assertion and returns an OCI `TokenExchangeSigner`; it does not run group/scope authorization because it has no requested downstream scope.
- `get_token_with_oci_credential()` is a separate OAuth token-exchange API for OCI signer dictionaries or OCI CLI profile names. Current code does not validate an end-user assertion and does not run group/scope authorization for that API.
- Vault-backed OAuth app values require the hosting runtime principal to read the referenced secrets.
- Direct creds, local key files, and inline PEM/cert values avoid Vault reads for those materials.
- `TOKEN_FACTORY_OCI_AUTH_MODE` and `TOKEN_FACTORY_OCI_AUTH_PROFILE` apply to factory-owned OCI clients generally, including Vault secret reads.

Hybrid validation notes:

- TokenFactory always validates caller assertions with hybrid validation: Identity Domain introspection must return `active=true`, and the same incoming JWT must validate against the Identity Domain signing keys.
- TokenFactory always discovers `issuer` and `jwks_uri` from `<domain_url>/.well-known/openid-configuration`; clients do not configure validation mode, issuer, JWKS URL, or a custom validator.
- TokenFactory copies the configured `groups_claim` from the validated JWT into the trusted claims so authorization can use custom signed claims that introspection omits.
- For a custom authorization claim such as `group`, set `TokenFactoryRuntimeConfig(groups_claim="group")` and keep authorization policy groups keyed by claim values such as `all_users`.
- Runtime access to the Identity Domain discovery document and JWKS endpoint is required.

Signed authorization policy notes:

- The security team owns the production groups/scope matrix. OCI Vault stores and distributes it, but Vault is not the root of trust.
- Primary control: developers must not have `manage keys` or `use keys` on the security-owned OCI KMS asymmetric signing key, and must not be able to alter the trusted signer bundle.
- Defense-in-depth: TokenFactory rejects the policy secret unless the signed envelope verifies against the trusted `key_id`, `key_version_id`, `algorithm`, and `public_key_pem`.
- `key_id` and `key_version_id` are OCI OCIDs used to match envelope metadata to a trusted signer entry. `public_key_pem` is the public key used for the offline signature verification, and it must correspond to that trusted OCI key version.
- The trusted signer bundle may be delivered through environment variables only when platform or security deployment ownership prevents non-security actors from changing those variables.
- TokenFactory verifies signatures offline and does not call OCI KMS `Verify` at runtime.

Logging notes:

- `TOKEN_FACTORY_LOG_LEVEL=DEBUG` enables the module's debug records, including `_factory_support.py` method-entry logs emitted through `LOGGER.debug(...)`.
- `FATAL` is accepted as an alias for `CRITICAL`; `WARN` is accepted as an alias for `WARNING`.
- `NOTSET` is a valid Python logging level, but it makes the `token_factory` logger inherit the effective level from parent/root logging configuration. Use `DEBUG` when you explicitly need debug output.
- The module sets the `token_factory` logger level directly so `TOKEN_FACTORY_LOG_LEVEL` still takes effect when another framework has already configured root logging. Existing handler-level filters, OCI Function/runtime log filters, or external log collectors can still suppress records after the logger emits them.


## Runtime Example

1. Set the following process variables for the hosting application. These values are provided by the bootstrap module.
```sh
export TOKEN_FACTORY_DOMAIN_URL="https://<domain>.identity.oraclecloud.com:443"
export TOKEN_FACTORY_DOMAIN_REGION="us-chicago-1"
export TOKEN_FACTORY_AUTHZ_POLICY_ENABLE="true"
export TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID="ocid1.vaultsecret.oc1..<authz-policy>"
export TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE="off"
export TOKEN_FACTORY_TIMEOUT_SECONDS="30"
```

2. Let Token Factory know about the hosting application. These values are provided by the bootstrap module.
```python
from token_factory import TokenFactory

factory = TokenFactory(
    oauth_apps={
        "orders-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-client-credentials>",
            "issuer": "https://orders-api.example.com/token-factory",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<orders-private-key>",
            "private_key_passphrase_secret_ocid": None,
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<orders-certificate>",
            "kid": "orders-api-token-factory-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        }
    }
)
```
If you do not use process-wide environment variables in step 1 above, pass the same runtime values into TokenFactory under the *runtime_config* map:

```python
from token_factory import TokenFactory

factory = TokenFactory(
    runtime_config={
        "domain_url": "https://<domain>.identity.oraclecloud.com:443",
        "domain_region": "us-chicago-1",
        "timeout_seconds": 30,
        "oci_auth_mode": "instance-principal",
        "oci_region": "us-chicago-1",
        "subject_claim": "sub",
        "groups_claim": "groups",
        "authz_policy_enable": True,
        "authz_policy_secret_ocid": "ocid1.vaultsecret.oc1..<authz-policy-secret>",
        "authz_policy_signature_mode": "off",
    },
    oauth_apps={
        "orders-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-client-credentials>",
            "issuer": "https://orders-api.example.com/token-factory",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<orders-private-key>",
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<orders-certificate>",
            "kid": "orders-api-token-factory-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        }
    },
)
```

3. Request token, specifying the token type, the required scope and the client_key (for the hosting component).
```python
result = factory.get_token(
    "<incoming-caller-access-token>",
    token_type="oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)

oauth_access_token = result["token"]
```

## Related Docs

- [docs/advanced-scenarios.md](./docs/advanced-scenarios.md)
- [docs/oci-compute-usage.md](./docs/oci-compute-usage.md)
- [samples/oci_compute_usage.py](./samples/oci_compute_usage.py)
- [Token Factory Bootstrap Module](../token-factory-bootstrap/README.md)
