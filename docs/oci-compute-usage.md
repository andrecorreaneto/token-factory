# TokenFactory OCI Compute Usage Guide

This guide shows application developers how to run TokenFactory from an OCI Compute instance after the OAuth client resolution and authorization model is enabled.

TokenFactory now has two distinct usage paths:

- `TokenFactory.get_token(...)` validates an incoming caller assertion, resolves the hosting component OAuth client from the configured `oauth_apps` entry selected by `client_key`, optionally authorizes scoped downstream requests, and then returns the requested downstream credential.
- `TokenFactory.get_token_with_oci_credential(...)` uses an OCI signer dictionary or OCI CLI profile for OAuth token exchange only. It does not validate an end-user assertion and does not run group-scope authorization.

## 1. Prepare the Compute Instance

Install Python dependencies from the cloned repo:

```bash
cd /path/to/token-factory
python3 -m pip install -r requirements.txt
```

For Vault-backed configuration on OCI Compute, use instance principals:

```bash
export TOKEN_FACTORY_OCI_AUTH_MODE="instance-principal"
export TOKEN_FACTORY_OCI_REGION="us-phoenix-1"
```

The Compute instance principal must be allowed to read every OCI Vault secret referenced by TokenFactory:

```text
allow dynamic-group <compute-dynamic-group> to read secret-bundles in compartment <secrets-compartment>
```

## 2. Configure TokenFactory

Set shared Identity Domain runtime configuration through environment variables. Provide hosting component OAuth client configuration through the `oauth_apps` argument when constructing `TokenFactory`. A single-client process uses one `oauth_apps` entry and still passes its `client_key` on each `get_token(...)` call.

```bash
export TOKEN_FACTORY_DOMAIN_URL="https://<domain>.identity.oraclecloud.com:443"
export TOKEN_FACTORY_DOMAIN_REGION="us-chicago-1"

export TOKEN_FACTORY_SUBJECT_CLAIM="sub"
export TOKEN_FACTORY_GROUPS_CLAIM="groups"
export TOKEN_FACTORY_AUTHZ_POLICY_ENABLE="true"
export TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID="ocid1.vaultsecret.oc1..<authz-policy-secret>"
export TOKEN_FACTORY_TIMEOUT_SECONDS="30"
```

For command-line runs, store the structured OAuth app map in a protected JSON file:

```json
{
  "orders-api": {
    "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<client-id-secret>",
    "issuer": "https://orders-api.example.com/",
    "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<private-key-secret>",
    "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<certificate-secret>",
    "kid": "orders-api-cert",
    "resource_audiences": [
      "orders-api"
    ],
    "required_incoming_scopes": [
      "orders-api.invoke"
    ]
  }
}
```

The same `oauth_apps` structure is used for one client or many clients. Multi-client processes add more entries and select the intended one with `client_key`.

For UPST-backed flows, include any propagation trust claim required by your IdentityPropagationTrust:

```bash
export TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM="upstclient:tokenexchange"
```

## 3. Provide an Authorization Policy

Authorization policy enforcement is opt-in and controlled only by `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE`. The default is `false`, which means TokenFactory does not run group-scope authorization checks for scoped requests. When `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`, `oauth` and `oracle-database` requests require a configured authorization policy and are denied if no policy is configured or no grant matches.

`TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID` configures the built-in Vault policy provider; it is not the enforcement switch. For development and local testing, keep the default raw JSON mode and store a JSON document like this in the secret referenced by `TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID`:

```json
{
  "version": 1,
  "grants": {
    "oauth": {
      "orders-readers": [
        "urn:opc:idm:orders.read"
      ],
      "orders-writers": [
        "urn:opc:idm:orders.read",
        "urn:opc:idm:orders.write"
      ]
    },
    "oracle-database": {
      "db-users": [
        "urn:oracle:db::id::*"
      ]
    }
  }
}
```

The incoming caller assertion must contain the group names in the configured groups claim. Scope matching is exact.

For production, use signed policy mode:

```bash
export TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE="on"
export TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT="prod"
export TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID="ocid1.tenancy.oc1..<prod-tenancy>"
export TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON='[
  {
    "key_id": "ocid1.key.oc1..<security-owned-kms-key>",
    "key_version_id": "ocid1.keyversion.oc1..<security-owned-kms-key-version>",
    "algorithm": "SHA_256_RSA_PKCS_PSS",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
]'
```

In signed mode, the Vault secret must contain a signed envelope with `version`, `metadata`, `policy`, and `signature`. `metadata.signing_key_id` is the OCI KMS asymmetric key OCID, `metadata.signing_key_version_id` is the exact key version OCID, and `metadata.policy_digest` is `sha256:` plus the digest of the canonical policy JSON.

The security team owns the production matrix and signing key. Developers must not have `manage keys` or `use keys` on that key, and must not be able to alter `TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON`. The signature check is a second layer that rejects a Vault secret modified without the security-owned signer.

## 4. Get an Incoming Caller Assertion

`get_token(...)` needs an end-user access token issued for the hosting component as resource server. TokenFactory validates that incoming assertion before trusting the subject or groups claims.

Provide it inline, from a file, or through `CALLER_ACCESS_TOKEN`:

```bash
export CALLER_ACCESS_TOKEN="<incoming-end-user-access-token>"
```

For production scripts, prefer a file or environment variable over command-line inline tokens so shell history does not capture bearer tokens.

## 5. Run the Sample Script

The sample is at:

```text
samples/oci_compute_usage.py
```

Run help first:

```bash
python3 samples/oci_compute_usage.py --help
```

Use `--dry-run` to verify command shape without calling Identity Domain or OCI:

```bash
python3 samples/oci_compute_usage.py oauth \
  --dry-run \
  --client-key orders-api \
  --scope "urn:opc:idm:orders.read" \
  --access-token "$CALLER_ACCESS_TOKEN"
```

Expected dry-run output:

```json
{
  "client_key": "orders-api",
  "credential_source": "inline",
  "method": "TokenFactory.get_token",
  "scope": "urn:opc:idm:orders.read",
  "token_type": "oauth"
}
```

## 6. Usage Patterns

### OAuth Downstream Token

Use this when the downstream system expects a regular OAuth access token.

```bash
python3 samples/oci_compute_usage.py oauth \
  --oauth-apps-json-file /secure/path/oauth_apps.json \
  --client-key orders-api \
  --scope "urn:opc:idm:orders.read" \
  --access-token-file /secure/path/incoming_access_token.txt
```

The sample redacts token values by default. Add `--show-token` only in controlled troubleshooting sessions.

### User ID Lookup

Use this when the application only needs the validated subject.

```bash
python3 samples/oci_compute_usage.py userid \
  --oauth-apps-json-file /secure/path/oauth_apps.json \
  --client-key orders-api \
  --access-token-file /secure/path/incoming_access_token.txt
```

This validates the incoming assertion and returns the configured subject claim. It does not exchange for a downstream OAuth token and does not run group-scope authorization.

### Oracle Database Scoped Token

Use this when the application needs a database scoped token and matching session key material.

```bash
python3 samples/oci_compute_usage.py oracle-database \
  --oauth-apps-json-file /secure/path/oauth_apps.json \
  --client-key orders-api \
  --scope "urn:oracle:db::id::*" \
  --access-token-file /secure/path/incoming_access_token.txt
```

This flow validates the incoming assertion, authorizes the database scope when `TOKEN_FACTORY_AUTHZ_POLICY_ENABLE=true`, uses the selected hosting component OAuth client ID for IdentityPropagationTrust, and requests the database scoped access token.

### OCI Service Signer

Use this when the application needs an OCI SDK `TokenExchangeSigner`.

```bash
python3 samples/oci_compute_usage.py oci-service \
  --oauth-apps-json-file /secure/path/oauth_apps.json \
  --client-key orders-api \
  --access-token-file /secure/path/incoming_access_token.txt
```

This validates the incoming assertion before creating the signer. There is no group-scope authorization step for `oci-service` because it has no caller-requested scope.

### OCI Credential OAuth Exchange

Use this separate API only when you intentionally want OCI-authenticated OAuth exchange without end-user assertion validation.

Using an OCI CLI profile:

```bash
python3 samples/oci_compute_usage.py oci-credential-oauth \
  --profile DEFAULT \
  --scope "urn:opc:idm:orders.read"
```

Using a signer dictionary file:

```bash
python3 samples/oci_compute_usage.py oci-credential-oauth \
  --credential-json-file /secure/path/oci_signer_credential.json \
  --scope "urn:opc:idm:orders.read"
```

Example signer dictionary:

```json
{
  "tenancy": "ocid1.tenancy.oc1..<tenancy>",
  "user": "ocid1.user.oc1..<user>",
  "fingerprint": "aa:bb:cc:dd",
  "region": "us-chicago-1",
  "private_key_file": "/home/opc/.oci/oci_api_key.pem"
}
```

## 7. Python Usage Patterns

### Single-Client `oauth_apps` Configuration

```python
from token_factory import TokenFactory

factory = TokenFactory(
    oauth_apps={
        "orders-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-creds>",
            "issuer": "https://orders-api.example.com/",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<orders-key>",
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<orders-cert>",
            "kid": "orders-api-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        },
    }
)

result = factory.get_token(
    credential=incoming_access_token,
    token_type="oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)

access_token = result["token"]
```

### User ID From Validated Assertion

```python
from token_factory import TokenFactory

factory = TokenFactory(
    oauth_apps={
        "orders-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-creds>",
            "issuer": "https://orders-api.example.com/",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<orders-key>",
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<orders-cert>",
            "kid": "orders-api-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        },
    }
)

result = factory.get_token(
    credential=incoming_access_token,
    token_type="userid",
    client_key="orders-api",
)

user_id = result["user_id"]
```

### Multi-Client `oauth_apps` Configuration

```python
from token_factory import TokenFactory

factory = TokenFactory(
    oauth_apps={
        "orders-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-creds>",
            "issuer": "https://orders-api.example.com/",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<orders-key>",
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<orders-cert>",
            "kid": "orders-api-cert",
            "resource_audiences": ["orders-api"],
            "required_incoming_scopes": ["orders-api.invoke"],
        },
        "profile-api": {
            "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<profile-creds>",
            "issuer": "https://profile-api.example.com/",
            "private_key_secret_ocid": "ocid1.vaultsecret.oc1..<profile-key>",
            "certificate_secret_ocid": "ocid1.vaultsecret.oc1..<profile-cert>",
            "kid": "profile-api-cert",
            "resource_audiences": ["profile-api"],
            "required_incoming_scopes": ["profile-api.invoke"],
        },
    }
)

result = factory.get_token(
    credential=incoming_access_token,
    token_type="oauth",
    scope="urn:opc:idm:orders.read",
    client_key="orders-api",
)
```

## 8. Troubleshooting

- `401` or `CallerAssertionValidationError`: the incoming assertion is inactive, cannot be introspected, has the wrong audience, or is missing required incoming scopes.
- `403` or `AuthorizationError`: authorization policy enforcement is enabled and the caller is validated, but no policy is configured or the configured groups do not grant every requested downstream scope.
- `AuthorizationPolicyError`: the policy secret is unreadable, invalid JSON, missing `version: 1`, malformed, unsigned when signature mode is `on`, signed by an untrusted key/version, expired, bound to the wrong environment/domain/tenant, or cryptographically invalid.
- `OAuthClientResolutionError`: the requested `client_key` is missing, unknown, or the selected OAuth client material cannot be loaded.
- `TokenExchangeError`: the downstream Identity Domain token exchange, UPST exchange, or database token generation failed.
