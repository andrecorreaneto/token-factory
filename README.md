# Token Factory

Token Factory is a Python library for applications that act on behalf of a user, such as an MCP server or an AI agent. The application receives the user's access token and needs a different credential for the next hop: an OAuth token for another API, a token for an Oracle Database, or a signer for OCI APIs. Token Factory checks the incoming token and then produces the credential the next hop expects.

Without it, every application would implement its own token validation, assertion signing, Identity Domain token exchange, Vault secret reads, and OCI signer setup. Token Factory keeps that logic, and its security configuration, in one place.

## Key concepts

- **Hosting app**: the application that embeds Token Factory, for example your MCP server. Each hosting app has its own OAuth app (client) in the OCI IAM Identity Domain. Token Factory acts as that OAuth app when it talks to the Identity Domain. Token Factory itself is not an OAuth client.
- **`oauth_apps` and `client_key`**: you describe each hosting app in an `oauth_apps` map when you create the factory, and name the one to use with `client_key` on every call. Most processes have exactly one entry.
- **Caller token**: the access token your application received from its caller. Token Factory validates it before trusting anything in it.
- **Token type**: what you want back. One of `oauth`, `oracle-database`, `oci-service`, or `userid`.
- **Two different scopes**: the `scope` you pass to `get_token` is what you are asking for *downstream*. The `required_incoming_scopes` setting is what the *incoming* caller token must already carry. They are unrelated.
- **Validation and authorization**: validation decides whether the caller token is genuine, meant for this app, and sent by an allowed client. Authorization, which is optional, decides whether the user's groups may request the downstream scope.
- **Bootstrap**: a [Terraform module](./bootstrap/) that provisions the Identity Domain apps, keys, trusts, Vault secrets, and IAM policies, and outputs the configuration this library needs.

## Choosing a token type

| You need | `token_type` | `credential` | `scope` | You get back |
| --- | --- | --- | --- | --- |
| An OAuth token for another API, on behalf of the user | `oauth` | caller token | required | dict with `token` |
| An OAuth token for the hosting app itself, with no user | `oauth` | `None` | required | dict with `token` |
| An Oracle Database token for the user | `oracle-database` | caller token | required (database scope) | tuple `(token, private_key_pem, ...)` |
| An Oracle Database token for the workload's own OCI identity | `oracle-database` | `"OCI_PRINCIPAL"` | required (database scope) | tuple `(token, private_key_pem, ...)` |
| An OCI SDK signer that calls OCI APIs as the user | `oci-service` | caller token | required only when authorization is on | OCI `TokenExchangeSigner` |
| Just the validated user ID | `userid` | caller token | not used | dict with `user_id` |

Use the separate `get_token_with_oci_credential()` API when you hold an OCI API key or OCI CLI profile and need an OAuth token. See [get_token_with_oci_credential](#get_token_with_oci_credential).

## Quick start

1. **Provision the prerequisites** with the [bootstrap module](./bootstrap/), usually through its [client folder](./bootstrap/client/). It outputs two sets of values: shared settings (`TF_SHARED_*`) and per-app settings (`TF_CLIENT_*`).

2. **Set the shared settings** as environment variables of the hosting application:

   ```sh
   export TF_SHARED_DOMAIN_URL="https://<domain>.identity.oraclecloud.com:443"
   export TF_SHARED_DOMAIN_REGION="us-chicago-1"
   export TF_SHARED_GROUPS_CLAIM="group"
   ```

3. **Describe the hosting app.** Token Factory does not read `TF_CLIENT_*` variables itself; your application maps them into an `oauth_apps` entry (see the [mapping table](#mapping-bootstrap-outputs-to-oauth_apps)):

   ```python
   from token_factory import TokenFactory

   factory = TokenFactory(
       oauth_apps={
           "ORDERS-API": {
               "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-client-credentials>",
               "issuer": "https://orders-api.example.com/token-factory",
               "kid": "orders-api-token-factory-cert",
               "kms_key_id": "ocid1.key.oc1..<orders-signing-key>",
               "kms_key_version_id": "ocid1.keyversion.oc1..<orders-signing-key-version>",
               "kms_crypto_endpoint": "https://<vault>-crypto.kms.us-chicago-1.oraclecloud.com",
               "resource_audiences": ["https://orders-api.example.com/"],
               "required_incoming_scopes": ["invoke"],
               "allowed_client_ids": ["<agent-client-id>"],
           }
       }
   )
   ```

   Creating the factory reads the shared settings and contacts the Identity Domain once to discover its endpoints. Create one factory per process and reuse it.

4. **Request a token:**

   ```python
   from token_factory import AuthorizationError, CallerAssertionValidationError

   try:
       result = factory.get_token(
           caller_access_token,
           "oauth",
           "https://inventory-api.example.com/inventory.read",
           client_key="ORDERS-API",
       )
       downstream_token = result["token"]
   except CallerAssertionValidationError:
       ...  # the caller token was rejected: respond 401
   except AuthorizationError:
       ...  # the user's groups may not request this scope: respond 403
   ```

## get_token

```python
result = factory.get_token(credential, token_type, scope=None, client_key="ORDERS-API")
```

| Parameter | Required | Description |
| --- | --- | --- |
| `credential` | yes | The caller token. Use `None` only for `oauth` without a user, and `"OCI_PRINCIPAL"` only for `oracle-database` with the workload's own identity. |
| `token_type` | yes | `oauth`, `oracle-database`, `oci-service`, or `userid`. |
| `scope` | depends | Required for `oauth` and `oracle-database`. Required for `oci-service` when authorization is on. Not used for `userid`. |
| `client_key` | yes | The `oauth_apps` key of the hosting app, even when there is only one. |

### oauth

With a caller token, Token Factory validates it, checks authorization when enabled, and then:

- returns the caller's token unchanged if it already has the requested scope and the matching audience, so no new token is needed; the result then includes `"source": "incoming_token"`;
- otherwise exchanges it at the Identity Domain for a new token issued for the same user, using an assertion signed by the hosting app's KMS key (the JWT bearer grant).

With `credential=None`, there is no user. Token Factory requests a token for the hosting app itself with its client ID and secret (the client credentials grant). No validation, authorization, or signing takes place.

Pass `scope` in the form the Identity Domain expects, usually the fully qualified scope, such as `https://inventory-api.example.com/inventory.read`.

The result is a dict with `token` (also available as `access_token`), `expires_in`, `token_type`, and `issued_token_type="oauth"`.

### oracle-database

```python
# As the user, through the user's OCI identity.
result = factory.get_token(caller_access_token, "oracle-database", db_scope, client_key="ORDERS-API")

# As the workload's own OCI identity (instance, resource principal, OKE workload, or profile).
result = factory.get_token("OCI_PRINCIPAL", "oracle-database", db_scope, client_key="ORDERS-API")

token, private_key_pem = result[0], result[1]
```

With a caller token, Token Factory exchanges the user's identity for an OCI user session through the hosting app's IdentityPropagationTrust, then requests a database token for `scope`. With `"OCI_PRINCIPAL"` (case-insensitive), it uses the workload's OCI identity directly, with no caller token, validation, or authorization. `"PROCESS"` is reserved and currently raises `NotImplementedError`.

The result unpacks as `(token, private_key_pem, expires_in, token_type, issued_token_type)`. It also has `principal_mode` (`user` or `oci_principal`) and `expires_at_epoch` attributes. If you pool database connections, key the pool by connect target, scope, and principal mode, and retire connections before `expires_at_epoch`.

### oci-service

Token Factory exchanges the user's identity for an OCI user session through the hosting app's IdentityPropagationTrust and returns an OCI SDK signer. OCI clients built with this signer call OCI APIs as the user, and OCI IAM policies for that user decide what each call may do.

When authorization is on, `scope` is required. It is a label your application chooses, such as the name of the MCP tool that needs OCI access, and Token Factory checks it against the policy. It is never sent to OCI and does not limit the signer.

### userid

Token Factory validates the caller token and returns `{"issued_token_type": "userid", "user_id": "<subject>"}`. Use it when you only need to know who the user is.

### Errors

| Error | Meaning | Typical response |
| --- | --- | --- |
| `CallerAssertionValidationError` | The caller token failed validation. | 401 |
| `AuthorizationError` | The user's groups may not request this scope. | 403 |
| `AuthorizationPolicyError` | The authorization policy could not be loaded or verified. | 500 |
| `OAuthClientResolutionError` | Unknown `client_key`, or the app's configuration is incomplete. | 500 |
| `ValueError` | Invalid arguments, such as an unsupported `token_type` or a missing `scope`. | 400 |
| `ConfigurationError` | Invalid configuration, an unreadable Vault secret or OCI identity, or (when creating the factory) failed Identity Domain discovery. | 500 |
| `TokenExchangeError` | The Identity Domain or OCI rejected an exchange, or its response could not be read. | 502 |

## get_token_with_oci_credential

```python
factory = TokenFactory()
result = factory.get_token_with_oci_credential("DEFAULT", scope="urn:opc:idm:orders.read")
```

Exchanges OCI API-key credentials for an OAuth token. `credential` is either an OCI CLI profile name from `~/.oci/config`, or a dict with `tenancy`, `user`, `fingerprint`, `region`, and exactly one of `private_key_file`, `private_key_file_location`, or `private_key_content`. `scope` is optional.

This API does not use `oauth_apps` or `client_key`, and does not validate a caller token or check authorization. The result has the same shape as an `oauth` result.

## How a caller token is validated

Whenever a request carries the caller's access token, Token Factory validates that token before doing anything else. That covers `oauth` on behalf of a user, `oracle-database` with a caller token, `oci-service`, and `userid`. The checks answer five questions: is the token still valid, is it genuine, is it meant for this app, was it sent by an allowed client, and who is the user.

1. **Pick the hosting app.** The request names the hosting app through `client_key`. Token Factory loads that app's settings: its OAuth client, the audiences and scopes it accepts, and the clients allowed to call it.
2. **Ask the Identity Domain whether the token is still valid.** Token Factory sends the token to the Identity Domain, identifying itself as the hosting app. If the Identity Domain says the token is not active (expired, revoked, unknown, or malformed), the request is rejected.
3. **Check that the token is meant for this app.** At least one of the token's audiences must be one of the app's `resource_audiences`.
4. **Check that the token carries an accepted scope.** If the app has `required_incoming_scopes`, the token must carry at least one of them.
5. **Check which client sent the token.** If the app has `allowed_client_ids`, the token's `client_id`, which identifies the OAuth client that obtained the token, must be the hosting app itself or one of the listed clients. A token that does not say which client obtained it is rejected. Without `allowed_client_ids`, any client is accepted.
6. **Check that the token is genuine.** Token Factory verifies the token's signature against the Identity Domain's published signing keys and confirms that the Identity Domain issued it and that it has not expired. The signed token must also carry the configured groups claim. The audience, scope, and client checks above are applied to the signed token too, so the token passes only if both the Identity Domain's answer and the token's own signature agree.
7. **Identify the user.** Token Factory reads the user from the subject claim (`sub` by default) and the user's groups from the groups claim, taking groups from the signed token because the Identity Domain's answer in step 2 does not include custom claims. A token with no subject is rejected.

Any failed check stops the request with `CallerAssertionValidationError`, and no downstream token is requested. The checks run on every request, even when Token Factory could reuse a cached result.

What validation does not prove: an access token is a bearer token, so a copy of it works from anywhere until it expires. `client_id` tells you which OAuth client obtained the token, not which machine is presenting it.

These checks are built into Token Factory. If you replace the built-in token validator with your own, Token Factory relies on yours to perform them.

Requests without a caller token skip validation: `oauth` with `credential=None`, `oracle-database` with `"OCI_PRINCIPAL"`, and `get_token_with_oci_credential()`.

## How authorization works

Authorization is off by default. Turn it on with `TF_SHARED_AUTHZ_POLICY_ENABLE=true` to control which users may request which downstream scopes.

When it is on, every `oauth`, `oracle-database`, and `oci-service` request that carries a caller token is checked after validation:

- The request must include a `scope`; a missing scope is rejected.
- Every requested scope must be granted to at least one of the user's groups. The user's groups count together, so different groups can grant different scopes. The decision depends only on groups, not on who the user is.
- Scopes must match the policy exactly, so grant a fully qualified scope if that is what your application requests.
- Grants are listed per token type: a scope granted under `oauth` does not count for `oracle-database` or `oci-service`.
- If no policy is configured, or the policy does not grant a scope, the request is refused with `AuthorizationError`.

`userid` and requests without a caller token are never checked, because there is no scope or no user to check.

The policy is a JSON document, usually stored in an OCI Vault secret referenced by `TF_SHARED_AUTHZ_POLICY_SECRET_OCID`:

```json
{
  "version": 1,
  "grants": {
    "oauth": {
      "all_users": ["https://inventory-api.example.com/inventory.read"]
    },
    "oracle-database": {
      "analysts": ["urn:oracle:db::id::<compartment-ocid>::<database-ocid>"]
    },
    "oci-service": {
      "cloud_ops": ["tools.get_oci_resources"]
    }
  }
}
```

Group names are the values of the groups claim in the caller token.

In production, the security team should own and sign the policy. With `TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE=on`, the secret holds a signed envelope, and Token Factory rejects it unless the signature verifies against one of the trusted signers in `TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON`. Verification happens locally; Token Factory does not call OCI KMS to verify. The protection depends on developers not being able to use the security team's KMS signing key or change the trusted signer list. Vault distributes the policy but is not what makes it trustworthy.

## Configuration reference

### Shared settings

Shared settings apply to the whole process. Token Factory reads them from environment variables, or you can pass the same values as a `runtime_config` dict (or `TokenFactoryRuntimeConfig`) when creating the factory.

| Environment variable | `runtime_config` key | Default | Purpose |
| --- | --- | --- | --- |
| `TF_SHARED_DOMAIN_URL` | `domain_url` | required | Identity Domain base URL, such as `https://<domain>.identity.oraclecloud.com:443`. |
| `TF_SHARED_DOMAIN_REGION` | `domain_region` | required | Region of the Identity Domain, used for the OCI user session and database token calls. |
| `TF_SHARED_TIMEOUT_SECONDS` | `timeout_seconds` | `30` | HTTP timeout. |
| `TF_SHARED_OCI_AUTH_MODE` | `oci_auth_mode` | `instance-principal` | How Token Factory authenticates its own OCI calls (KMS signing, Vault reads, `OCI_PRINCIPAL`): `instance-principal`, `resource-principal`, `oke-workload-identity`, or `oci-profile`. |
| `TF_SHARED_OCI_AUTH_PROFILE` | `oci_auth_profile` | `DEFAULT` | OCI CLI profile for `oci-profile` mode. |
| `TF_SHARED_OCI_REGION` | `oci_region` | from the secret OCID | Region for Vault secret reads. |
| `TF_SHARED_SUBJECT_CLAIM` | `subject_claim` | `sub` | Claim that holds the user ID. |
| `TF_SHARED_GROUPS_CLAIM` | `groups_claim` | `groups` | Claim that holds the user's groups. Caller tokens without it are rejected. The bootstrap sets `group`. |
| `TF_SHARED_AUTHZ_POLICY_ENABLE` | `authz_policy_enable` | `false` | Turns authorization on. |
| `TF_SHARED_AUTHZ_POLICY_SECRET_OCID` | `authz_policy_secret_ocid` | none | Vault secret with the policy JSON, or the signed envelope when signature mode is `on`. |
| `TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE` | `authz_policy_signature_mode` | `off` | `on` requires a signed policy. Use `on` in production. |
| `TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON` | `authz_trusted_signers` | none | Required when signature mode is `on`. JSON list of `{key_id, key_version_id, algorithm, public_key_pem}`, with `algorithm` set to `SHA_256_RSA_PKCS_PSS`. |
| `TF_SHARED_AUTHZ_POLICY_ENVIRONMENT` | `authz_policy_environment` | none | If set, the signed policy's `metadata.environment` must match. |
| `TF_SHARED_AUTHZ_POLICY_TENANT_ID` | `authz_policy_tenant_id` | none | If set, the signed policy's `metadata.tenant_id` must match. |
| `TF_SHARED_CACHE_ENABLE` | `cache_enable` | `false` | Reuse unexpired results within one factory. Validation and authorization still run on every request. |
| `TF_SHARED_CACHE_MAX_SIZE` | `cache_max_size` | `1024` | Cache size; the least recently used entry is evicted first. |
| `TF_SHARED_LOG_LEVEL` | none | `INFO` | Level of the `token_factory` logger: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, or `NOTSET` (`FATAL` and `WARN` are aliases). |
| `TF_SHARED_LOG_FULL_ASSERTION` | `log_full_assertion` | `false` | Logs complete tokens. Troubleshooting only: logged tokens can be replayed. |

Boolean settings accept `1`, `true`, `yes`, `y`, or `on`.

### oauth_apps

Each entry describes one hosting app. Values can be plain dicts or `OAuthClientInfo` objects.

| Field | Needed for | Purpose |
| --- | --- | --- |
| `client_credentials` or `client_credentials_secret_ocid` | all requests | The app's `client_id:client_secret`, given directly or as a Vault secret that contains exactly that text. Use the Vault secret in production. |
| `issuer` | requests with a caller token | Issuer of the assertions the app signs. It must match the app's IdentityPropagationTrust. |
| `kid` | requests that sign assertions | Key ID placed in signed assertions. It must match the alias of the app's certificate in the Identity Domain. |
| `kms_key_id`, `kms_key_version_id`, `kms_crypto_endpoint` | requests that sign assertions | The OCI KMS key, exact key version, and Vault cryptographic endpoint used to sign. The private key never leaves KMS. |
| `resource_audiences` | requests with a caller token | Audiences the caller token may have. An empty list skips the audience check, so use it only in tests. |
| `required_incoming_scopes` | optional | Scopes the caller token may carry; at least one is required. Empty skips the check. |
| `allowed_client_ids` | optional | OAuth client IDs allowed to send caller tokens. Unset (`None`) skips the check. The app's own client ID is always allowed, so `[]` means only the app itself. |
| `propagation_trust_claim` | `oracle-database` and `oci-service` with a caller token, when the trust requires it | Extra claim for the IdentityPropagationTrust, written as `name:value`, such as `upstclient:tokenexchange`. |

"Requests that sign assertions" are `oauth` exchanges with a caller token, `oracle-database` with a caller token, and `oci-service`. `oauth` without a caller token needs only the client credentials.

### Mapping bootstrap outputs to oauth_apps

The bootstrap outputs one `TF_CLIENT_*` set per hosting app. Your application turns each set into an `oauth_apps` entry:

| Bootstrap output | `oauth_apps` | Notes |
| --- | --- | --- |
| `TF_CLIENT_KEY` | the entry's key | Pass it as `client_key`. |
| `TF_CLIENT_CREDS_SECRET_OCID` | `client_credentials_secret_ocid` | |
| `TF_CLIENT_ISSUER` | `issuer` | |
| `TF_CLIENT_KID` | `kid` | |
| `TF_CLIENT_KMS_KEY_ID` | `kms_key_id` | |
| `TF_CLIENT_KMS_KEY_VERSION_ID` | `kms_key_version_id` | |
| `TF_CLIENT_KMS_CRYPTO_ENDPOINT` | `kms_crypto_endpoint` | |
| `TF_CLIENT_RESOURCE_AUDIENCES` | `resource_audiences` | Comma-separated list. |
| `TF_CLIENT_REQUIRED_INCOMING_SCOPES` | `required_incoming_scopes` | Comma-separated list. |
| `TF_CLIENT_ALLOWED_CLIENT_IDS` | `allowed_client_ids` | Comma-separated list. Absent means `None` (check off); an empty string means `[]` (only the app itself). |
| `TF_CLIENT_PROPAGATION_TRUST_CLAIM` | `propagation_trust_claim` | |

For more control, such as loading app settings from your own store, pass an `oauth_client_resolver` instead of `oauth_apps`. See [advanced scenarios](./docs/advanced-scenarios.md).

## Identity Domain and OCI setup

The [bootstrap module](./bootstrap/) sets all of this up. This section explains what it creates and why, for review or manual setup.

**OAuth app per hosting app.** A confidential app in the Identity Domain named by `TF_SHARED_DOMAIN_URL`, with the Client Credentials and JWT Assertion grants enabled. Token Factory uses it to ask the Identity Domain about caller tokens and to exchange tokens. To receive caller tokens, the app must be a resource server whose audience appears in `resource_audiences`.

**Signing key and certificate.** Each hosting app signs assertions with an asymmetric OCI KMS key. A certificate for that key version is registered in the Identity Domain under the alias `kid`, so the Identity Domain can verify what the app signs. When you rotate the key version, publish a new certificate with a new `kid`.

**IdentityPropagationTrust.** Needed for `oracle-database` with a caller token and for `oci-service`. It lets the Identity Domain exchange a user assertion signed by the hosting app for an OCI user session. It must:

- have `issuer` equal to the app's `issuer`;
- hold the certificate of the app's KMS signing key version as `publicCertificate`;
- list the app's client ID in `oauthClients`;
- map the assertion's `sub` to users (`subjectClaimName: "sub"`, `subjectMappingAttribute: "userName"`);
- if it requires a client claim (`clientClaimName` and `clientClaimValues`), match the app's `propagation_trust_claim`.

**OCI IAM for the runtime.** The identity that runs the hosting app needs:

- `use keys` on its KMS signing key, to sign assertions;
- `read secret-bundles` on its Vault secrets: the client credentials and, if used, the authorization policy;
- for `oracle-database` with `OCI_PRINCIPAL`, the database access its own identity requires.

The bootstrap restricts these policies to the exact runtime (instance, function, or OKE namespace and service account) and the exact key and secrets.

## Troubleshooting

- **Every caller token is rejected with a missing claim.** The token lacks the groups claim. Set `TF_SHARED_GROUPS_CLAIM` to the claim your Identity Domain uses (the bootstrap uses `group`). Tokens issued to an application with no user usually carry no groups and are rejected.
- **`is not an allowed client of the selected hosting component`.** The caller's OAuth client is not in `allowed_client_ids`. Add its client ID, or, with the bootstrap, add its `oauth_apps` key to `allowed_clients`.
- **`400 invalid_scope` from the Identity Domain.** The requested scope does not exist, or the requesting app is not allowed to request it. Requests often need the fully qualified form, such as `https://playground.mcp.server/tools.get_user_info`, while the issued token contains only `tools.get_user_info`.
- **`400 invalid_request` after configuration changes.** Check the app's grants, the certificate alias (`kid`), and that the certificate matches the KMS key version in use.
- **Factory creation fails.** Token Factory could not read the Identity Domain's discovery document at `<TF_SHARED_DOMAIN_URL>/.well-known/openid-configuration`. The runtime needs network access to it and to the endpoints it lists.
- **Need more detail.** Set `TF_SHARED_LOG_LEVEL=DEBUG`. If your framework configures logging, its handlers can still filter these records.

## Related docs

- [Advanced scenarios](./docs/advanced-scenarios.md)
- [Using Token Factory on OCI Compute](./docs/oci-compute-usage.md)
- [Sample command-line client](./samples/oci_compute_usage.py)
- [Bootstrap module](./bootstrap/)
