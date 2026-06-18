# Token Factory

`TokenFactory` is a small client library that converts an incoming caller credential into the exact credential format a downstream target needs. Instead of making every client implement its own JWT assertion signing, Identity Domain token exchange, UPST handling, Vault secret retrieval, and OCI signer setup, this module provides one consistent entry point through `TokenFactory()` and `TokenFactory.get_token()`.

This is important because the supported targets in this repo do not all consume the same kind of credential. Some consumers need an OAuth access token, some need a user identifier, some need an OCI `TokenExchangeSigner`, and Oracle Database flows need a scoped database token plus the matching session key material. `TokenFactory` centralizes those translations so that clients can stay small, reuse the same security configuration, and avoid duplicating fragile trust, certificate, and secret-management logic across multiple services or scripts.

`TokenFactory` requires pre-existing configuration in OCI. The required configuration provisioning is automated using the [bootstrap terraform module](./bootstrap/). Make sure to read the [module's README](./bootstrap/README.md) for correct bootstrapping.

## `get_token` API

The main client entry point is:

```python
factory = TokenFactory()
result = factory.get_token(credential, target_tool, scope=None)
```

`TokenFactory()` loads the shared runtime configuration once, and `get_token()` performs the actual exchange for the requested downstream target. Pass a config override dictionary to `TokenFactory(CONFIG_OVERRIDES)` when you want local or test-specific values. `TokenFactory.from_env(CONFIG_OVERRIDES)` remains available as a named alias for compatibility and for callers that prefer the explicit env-loading name.

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `credential` | yes | The caller credential to exchange. This is usually an incoming access token string. For `oauth` and `userid`, it may also be an OCI signer dictionary or an OCI CLI profile name such as `DEFAULT`. |
| `target_tool` | yes | The requested output type. Supported values are `oracle-database`, `oci-service`, `oauth`, and `userid`. |
| `scope` | depends on flow | Required for `oracle-database`. Optional for `oauth` and `userid`. Not used for `oci-service`. |

### Accepted `credential` shapes

| Credential shape | Supported flows | Notes |
| --- | --- | --- |
| Access token string | all flows | Required for `oracle-database` and `oci-service`. For `oauth` and `userid`, this triggers the JWT assertion flow. |
| OCI signer dictionary | `oauth`, `userid` | Must include `tenancy`, `user`, `fingerprint`, `region`, and exactly one of `private_key_file`/`private_key_file_location` or `private_key_content`. Optional passphrase keys are `pass_phrase` or `private_key_passphrase`. |
| OCI CLI profile name | `oauth`, `userid` | Any non-token string is treated as a profile name and loaded from `~/.oci/config`. |

### Return value

`get_token()` returns different result types depending on `target_tool`:

- `oracle-database`: a tuple containing `(token, private_key_pem, expires_in, token_type, issued_token_type)`; the token and private key are always the first two elements
- `oci-service`: an OCI `TokenExchangeSigner`
- `oauth`: a dictionary containing `token`, `expires_in`, `token_type`, and `issued_token_type`
- `userid`: a dictionary containing `user_id` and `issued_token_type`

### Validation and common errors

- Unsupported `target_tool` values raise `ValueError`.
- `oracle-database` raises `ValueError` if `scope` is missing.
- `oracle-database` and `oci-service` raise `ValueError` if `credential` is not a non-empty access token string.
- Configuration issues raise `ConfigurationError`.
- Upstream exchange or decode failures raise `TokenExchangeError`.

## Supported Flows

Once you know the downstream consumer, selecting a flow is straightforward:

- Choose `oracle-database` when the caller needs a scoped Oracle Database token and the matching session private key material.
- Choose `oci-service` when the caller needs an OCI SDK signer rather than a bearer token string.
- Choose `oauth` when the downstream system expects a regular OAuth access token.
- Choose `userid` when the caller only needs the resolved subject identifier and does not need to keep the exchanged token.

The table below is a quick handout for clients integrating with the library. It shows what input each flow expects, what comes back, and which external trust or OCI components are involved.

| `target_tool` | Accepted credential types | Extra input | Returned token or value | Main upstream dependencies |
| --- | --- | --- | --- | --- |
| `oracle-database` | caller access token string | `scope` required | Oracle Database scoped access token plus session private key as the first two tuple elements | JWT assertion signing, IdentityPropagationTrust, `TokenExchangeSigner`, Identity Data Plane `generate_scoped_access_token` |
| `oci-service` | caller access token string | no scope | OCI `TokenExchangeSigner` backed by a UPST, not a raw token string | JWT assertion signing, IdentityPropagationTrust, `TokenExchangeSigner` |
| `oauth` | caller access token string, OCI signer dict, or OCI CLI profile name | `scope` optional | OAuth access token in the response payload (`issued_token_type=oauth`) | Identity Domain `/oauth2/v1/token`, JWT bearer grant or OCI request signer token exchange |
| `userid` | caller access token string, OCI signer dict, or OCI CLI profile name | `scope` optional | extracted `user_id` value, derived from the returned OAuth access token (`issued_token_type=userid`) | same as `oauth`, then local JWT decode of returned access token |


## Required Runtime Configuration

`TokenFactory` requires pre-existing configuration in OCI. The required configuration provisioning is automated using the [bootstrap terraform module](./bootstrap/). Make sure to read the [module's README](./bootstrap/README.md) for correct bootstrapping.

`TokenFactory` can run in two configuration-source modes:

- **Vault-backed production mode**: one or more `*_OCID` variables are set, such as `TOKEN_FACTORY_CREDS_SECRET_OCID`, `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID`, `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID`, or `TOKEN_FACTORY_CERT_SECRET_OCID`. In this mode, `TokenFactory` must authenticate to OCI so it can read those Vault secrets. Use `TOKEN_FACTORY_OCI_AUTH_MODE=instance-principal` (default) for OCI runtimes with instance-principal identity, `TOKEN_FACTORY_OCI_AUTH_MODE=resource-principal` for OCI resource-principal runtimes such as OCI Functions, or `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile` for a local/user-principal OCI CLI profile. The principal must have an IAM policy that grants read access to the referenced secrets.
- **Direct/local configuration mode**: none of the `*_OCID` secret variables are set. In this mode, credentials, signing key material, and certificate material come from direct values or local files, and `TokenFactory` does not need to authenticate to OCI just to load its own runtime configuration.

Production environments should use the `*_OCID` configuration variables so sensitive client credentials, private keys, and certificates stay in OCI Vault instead of process environment variables or local files. Direct/local configuration is intended for development, tests, and controlled local troubleshooting.

When Vault-backed mode is used, add an IAM policy for the principal that runs `TokenFactory`. For example, grant the function dynamic group or user group permission to read secret bundles in the compartment that contains the referenced secrets. The exact policy subject depends on the runtime identity you choose, but the policy must cover every secret OCID configured through `TOKEN_FACTORY_CREDS_SECRET_OCID`, `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID`, `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID`, and `TOKEN_FACTORY_CERT_SECRET_OCID`.

`TokenFactory` loads configuration from environment variables by default. These are the settings `factory.py` and [`_factory_support.py`](./_factory_support.py) expect:

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOKEN_FACTORY_DOMAIN_URL` | yes | Identity Domain base URL, for example `https://<domain>.identity.oraclecloud.com:443` |
| `TOKEN_FACTORY_DOMAIN_REGION` | yes | OCI region used for `TokenExchangeSigner` and Identity Data Plane calls |
| `TOKEN_FACTORY_CREDS_SECRET_OCID` | yes, unless `TOKEN_FACTORY_CREDS` is set | OCI Vault secret OCID containing `client_id:client_secret` for the token-factory confidential app; recommended for production |
| `TOKEN_FACTORY_CREDS` | yes, unless `TOKEN_FACTORY_CREDS_SECRET_OCID` is set | Direct `client_id:client_secret` value for the token-factory confidential app |
| `TOKEN_FACTORY_ISSUER` | yes | JWT `iss` claim used when building assertions; this must match the configured trust issuer |
| `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID` or `TOKEN_FACTORY_PRIVATE_KEY_PATH` or `TOKEN_FACTORY_PRIVATE_KEY_PEM` | yes, one of them | RSA private key used to sign JWT assertions; lookup order is secret OCID, then path, then inline PEM; secret OCID is recommended for production |
| `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID` or `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE` | no | Passphrase for the private key when the key is encrypted; secret OCID is recommended for production and takes precedence over the direct value |
| `TOKEN_FACTORY_CERT_SECRET_OCID` or `TOKEN_FACTORY_CERT_PATH` or `TOKEN_FACTORY_CERT_PEM` | yes, one of them | X.509 certificate that matches the private key; lookup order is secret OCID, then path, then inline PEM; secret OCID is recommended for production |
| `TOKEN_FACTORY_KID` | strongly recommended | JWT `kid` header used by `oauth` and `userid` assertions; see certificate-store notes below |
| `TOKEN_FACTORY_OCI_REGION` | optional | Region override for OCI Vault secret reads; otherwise the code derives the region from the secret OCID |
| `TOKEN_FACTORY_OCI_AUTH_MODE` | optional | OCI auth mode for factory-owned OCI SDK clients when `*_OCID` secrets are used: `instance-principal` (default), `resource-principal`, or `oci-profile` |
| `TOKEN_FACTORY_OCI_AUTH_PROFILE` | optional | OCI CLI profile name used for user-principal auth when `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile`; defaults to `DEFAULT` |
| `TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM` | optional | Additional claim in `claim_name:claim_value` format, injected only for `oracle-database` and `oci-service` |
| `TOKEN_FACTORY_TIMEOUT_SECONDS` | optional | HTTP timeout in seconds, default `30` |
| `TOKEN_FACTORY_LOG_FULL_ASSERTION` | optional | Enables full compact JWT logging; useful for debugging, but replay-sensitive |
| `TOKEN_FACTORY_LOG_LEVEL` | optional | Module logger level for the `token_factory` logger; defaults to `INFO`. Accepted values are `CRITICAL`, `FATAL`, `ERROR`, `WARNING`, `WARN`, `INFO`, `DEBUG`, and `NOTSET`. Values are case-insensitive. |

The OCI and Identity Domain related configuration used as inputs to the variables above can be provisioned by the [bootstrap terraform module](./bootstrap/). Make sure to read the [module's README](./bootstrap/README.md) for correct bootstrapping.

Important behavior details:

- The code requires both a signing private key source and a signing certificate source at config-load time.
- The configured certificate should match the configured private key because Identity Domain trust validation depends on that pair being consistent.
- Credentials are resolved in this order: `TOKEN_FACTORY_CREDS_SECRET_OCID`, then `TOKEN_FACTORY_CREDS`.
- Signing-key material is resolved in this order: `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID`, then `TOKEN_FACTORY_PRIVATE_KEY_PATH`, then `TOKEN_FACTORY_PRIVATE_KEY_PEM`.
- Signing-key passphrase material is resolved in this order: `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID`, then `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE`.
- Certificate material is resolved in this order: `TOKEN_FACTORY_CERT_SECRET_OCID`, then `TOKEN_FACTORY_CERT_PATH`, then `TOKEN_FACTORY_CERT_PEM`.
- When direct creds, local key files, or inline PEM/cert values are used, and none of the `*_OCID` secret variables are configured, the factory does not send signed OCI requests to load its own runtime configuration.
- In Vault-backed mode, factory-owned OCI SDK clients authenticate with instance principals by default.
- When `TOKEN_FACTORY_OCI_AUTH_MODE=resource-principal`, the factory uses the OCI SDK resource principal signer directly. This is the expected mode for OCI Functions and other resource-principal runtimes.
- When `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile`, the factory falls back to a local user-principal OCI API-key signer loaded from `~/.oci/config` (profile defaults to `DEFAULT`).
- The `TOKEN_FACTORY_OCI_AUTH_MODE` and `TOKEN_FACTORY_OCI_AUTH_PROFILE` settings apply to factory-owned OCI clients generally, not only Vault secret reads.
- When `credential` is a profile name such as `DEFAULT`, `oauth` and `userid` also depend on a readable local `~/.oci/config`.

Logging notes:

- `TOKEN_FACTORY_LOG_LEVEL=DEBUG` enables the module's debug records, including `_factory_support.py` method-entry logs emitted through `LOGGER.debug(...)`.
- `FATAL` is accepted as an alias for `CRITICAL`; `WARN` is accepted as an alias for `WARNING`.
- `NOTSET` is a valid Python logging level, but it makes the `token_factory` logger inherit the effective level from parent/root logging configuration. Use `DEBUG` when you explicitly need debug output.
- The module sets the `token_factory` logger level directly so `TOKEN_FACTORY_LOG_LEVEL` still takes effect when another framework has already configured root logging. Existing handler-level filters, OCI Function/runtime log filters, or external log collectors can still suppress records after the logger emits them.

### Library Dependencies

The module imports and uses:

- `PyJWT`
- `requests`
- `cryptography`
- `oci`
- OCI SDK classes: `TokenExchangeSigner`, `Signer`, `SecretsClient`, `DataplaneClient`

The Python package requirements checked into this package are in [`requirements.txt`](./requirements.txt):

```text
cryptography>=41.0.0
oci>=2.168.1
PyJWT>=2.8.0
requests>=2.31.0
```

## Identity Domain Pre-requisites

### 1. Confidential OAuth app client for token-factory

Create a confidential app client in the same Identity Domain used by `TOKEN_FACTORY_DOMAIN_URL`.

This app is the token-factory client used against `/oauth2/v1/token`. Its client ID/client secret pair can be stored in the Vault secret referenced by `TOKEN_FACTORY_CREDS_SECRET_OCID`, or supplied directly through `TOKEN_FACTORY_CREDS` for local-only setups.

Required grant types:

- enable `Client Credentials`
- enable `JWT Assertion`

Operational notes:

- The Vault secret value must be exactly `client_id:client_secret`.
- For UPST-backed flows (`oracle-database`, `oci-service`), the app client ID must also be listed in the `oauthClients` array of the `IdentityPropagationTrust`.
- If the Identity Domain token endpoint starts returning `400 invalid_request` after scope changes, also check [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md).

### 2. IdentityPropagationTrust for UPST (User Principal Service Token) Flows

`oracle-database` and `oci-service` depend on an IdentityPropagationTrust because the module signs a JWT assertion and exchanges it into a UPST-backed signer.

The trust must be aligned with the module configuration:

- `issuer` must equal `TOKEN_FACTORY_ISSUER`
- `publicCertificate` must represent the same certificate/private-key pair configured through `TOKEN_FACTORY_CERT_*` and `TOKEN_FACTORY_PRIVATE_KEY_*`
- `oauthClients` must include the token-factory confidential app client ID
- `subjectClaimName` should remain compatible with the module's JWT payload, which uses `sub`
- if your trust requires a client claim, configure `TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM` in `claim_name:claim_value` format

In this repo, the common propagation-claim pattern is:

```text
TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM="upstclient:tokenexchange"
```

That maps cleanly to an IdentityPropagationTrust using:

- `clientClaimName: "upstclient"`
- `clientClaimValues: ["tokenexchange"]`

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
    "oauthClients": ["<token-factory-client-id>"],
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

The example above matches the creation pattern already captured in [`../../../deploy/REQUIREMENTS.md`](../../../deploy/REQUIREMENTS.md).

### 3. Identity Domain certificate store and `TOKEN_FACTORY_KID`

For `oauth` and `userid`, this module sends JWT bearer assertions to the Identity Domain token endpoint. The intended production setup is:

- load the token-factory public key certificate into the Identity Domain certificate store
- set the certificate alias to exactly match `TOKEN_FACTORY_KID`
- configure the same certificate locally through `TOKEN_FACTORY_CERT_*`
- configure the matching private key through `TOKEN_FACTORY_PRIVATE_KEY_*`

Why this matters:

- `factory.py` adds `{"kid": TOKEN_FACTORY_KID}` to the JWT header for `oauth` and `userid` when `TOKEN_FACTORY_KID` is set
- Identity Domain uses that alias to locate the certificate that validates the assertion signature
- the local certificate is still required because this class-based configuration loader demands a certificate source, and the external Identity Domain validation still depends on the certificate matching the signing key

If `TOKEN_FACTORY_KID` is omitted, the library falls back to the Identity Domain `SIGNING_KEY` alias for `oauth` and `userid`. That fallback exists in code, but an explicit `TOKEN_FACTORY_KID` is the clearer and more controlled setup.

## OCI Vault secret requirements

The module can load its signing material and app credentials from OCI Vault.

Expected secret contents when Vault-backed sources are used:

- `TOKEN_FACTORY_CREDS_SECRET_OCID`: plain text `client_id:client_secret`
- `TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID`: PEM-encoded RSA private key
- `TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID`: plain text private-key passphrase
- `TOKEN_FACTORY_CERT_SECRET_OCID`: PEM-encoded X.509 certificate

**Notes**:

- Secret bundle content is base64-decoded and then treated as UTF-8 text, so PEM text is the safest format for key and certificate secrets.
- If `TOKEN_FACTORY_OCI_REGION` is not set, the secret's region is derived from the OCID.
- If any `*_OCID` source is configured, the runtime principal must be able to read every referenced secret. Use a dynamic group for instance-principal and resource-principal runtimes, or a user group for `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile`.
- Example of dynamic-group matching rules:

  ```text
  # Instance principal: all compute instances in one compartment.
  ALL {instance.compartment.id = '<instance-compartment-ocid>'}

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

  Use `where target.secret.id='<secret-ocid>'` when you want to restrict access to a specific configured secret.
- Factory-owned OCI SDK clients use Instance Principals by default. `TOKEN_FACTORY_OCI_AUTH_MODE=resource-principal` uses Resource Principals directly, and `TOKEN_FACTORY_OCI_AUTH_MODE=oci-profile` enables local OCI API-key profile fallback.
- Vault reads are skipped for any material supplied through `TOKEN_FACTORY_CREDS`, `TOKEN_FACTORY_PRIVATE_KEY_PATH`, `TOKEN_FACTORY_PRIVATE_KEY_PEM`, `TOKEN_FACTORY_CERT_PATH`, or `TOKEN_FACTORY_CERT_PEM`. If all runtime material is supplied this way and no `*_OCID` secret variables are configured, `TokenFactory` does not need OCI authentication for configuration loading.

## Credential-specific Dependencies

`oauth` and `userid` accept three credential shapes:

1. Access token string
   Uses the token-factory JWT assertion flow and therefore depends on the confidential app client, signing key/certificate, and Identity Domain certificate-store setup.

2. OCI signer dictionary
   Must contain `tenancy`, `user`, `fingerprint`, `region`, and exactly one of `private_key_file`/`private_key_file_location` or `private_key_content`. Optional passphrase keys are `pass_phrase` or `private_key_passphrase`.

3. OCI CLI profile name
   Must resolve through `oci.config.from_file(profile_name=<name>)`, so `~/.oci/config` and the referenced private key material must be present and readable.

## Minimal Environment Example

```sh
export TOKEN_FACTORY_DOMAIN_URL="https://<domain>.identity.oraclecloud.com:443"
export TOKEN_FACTORY_DOMAIN_REGION="us-chicago-1"
export TOKEN_FACTORY_OCI_REGION="us-phoenix-1"
export TOKEN_FACTORY_CREDS_SECRET_OCID="ocid1.vaultsecret.oc1..<token-factory-app-secret>"
export TOKEN_FACTORY_ISSUER="https://upst.tokenfactory/"
export TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID="ocid1.vaultsecret.oc1..<jwt-private-key>"
# export TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID="ocid1.vaultsecret.oc1..<jwt-private-key-passphrase>"
export TOKEN_FACTORY_CERT_SECRET_OCID="ocid1.vaultsecret.oc1..<jwt-certificate>"
export TOKEN_FACTORY_KID="token-factory-cert"
export TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM="upstclient:tokenexchange"
export TOKEN_FACTORY_TIMEOUT_SECONDS="30"
```

## Local-only Environment Example

```sh
export TOKEN_FACTORY_DOMAIN_URL="https://<domain>.identity.oraclecloud.com:443"
export TOKEN_FACTORY_DOMAIN_REGION="us-chicago-1"
export TOKEN_FACTORY_CREDS="client-id:client-secret"
export TOKEN_FACTORY_ISSUER="https://upst.tokenfactory/"
export TOKEN_FACTORY_PRIVATE_KEY_PATH="$HOME/.oci/token-factory-private-key.pem"
export TOKEN_FACTORY_CERT_PATH="$HOME/.oci/token-factory-cert.pem"
export TOKEN_FACTORY_KID="token-factory-cert"
export TOKEN_FACTORY_TIMEOUT_SECONDS="30"
```

## Code Examples

These examples assume the environment variables above are already set and that `TokenFactory` can be created with `TokenFactory()`.

### `oracle-database`

```python
from token_factory import TokenFactory

caller_access_token = "<caller-access-token>"
database_scope = "urn:oracle:db::id::*"

factory = TokenFactory()
db_token, session_private_key_pem, expires_in, token_type, issued_token_type = factory.get_token(
    caller_access_token,
    "oracle-database",
    scope=database_scope,
)
```

### `oci-service`

```python
from oci.identity import IdentityClient
from token_factory import TokenFactory

caller_access_token = "<caller-access-token>"

factory = TokenFactory()
signer = factory.get_token(caller_access_token, "oci-service")

identity_client = IdentityClient(config={"region": "us-chicago-1"}, signer=signer)
regions = identity_client.list_regions().data
```

### `oauth`

```python
from token_factory import TokenFactory

caller_access_token = "<caller-access-token>"
oauth_scope = "urn:opc:idm:__myscope__"

factory = TokenFactory()
result = factory.get_token(caller_access_token, "oauth", scope=oauth_scope)

oauth_access_token = result["token"]
token_type = result["token_type"]
expires_in = result["expires_in"]
```

You can also use an OCI CLI profile name instead of an access token for `oauth`:

```python
from token_factory import TokenFactory

factory = TokenFactory()
result = factory.get_token("DEFAULT", "oauth", scope="urn:opc:idm:__myscope__")

oauth_access_token = result["token"]
```

### `userid`

```python
from token_factory import TokenFactory

caller_access_token = "<caller-access-token>"

factory = TokenFactory()
result = factory.get_token(caller_access_token, "userid")

user_id = result["user_id"]
```

You can also call `userid` with an OCI signer dictionary:

```python
from token_factory import TokenFactory

credential = {
    "tenancy": "ocid1.tenancy.oc1..<tenancy>",
    "user": "ocid1.user.oc1..<user>",
    "fingerprint": "aa:bb:cc:dd",
    "region": "us-chicago-1",
    "private_key_content": "<pem-private-key>",
}

factory = TokenFactory()
result = factory.get_token(credential, "userid")

user_id = result["user_id"]
```

## Related Repo Docs

- [`../../../deploy/REQUIREMENTS.md`](../../../deploy/REQUIREMENTS.md)
- [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md)
