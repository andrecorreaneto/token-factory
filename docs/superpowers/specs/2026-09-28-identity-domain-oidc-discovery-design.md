# Identity Domain OIDC Discovery Design

## Summary

Token Factory will treat `identity_domain_url` as the authoritative Identity Domain base URL and derive every runtime OAuth/OIDC value published by its OpenID Provider Configuration document. Each `TokenFactory` will load and validate that document once during construction and retain an immutable metadata snapshot for its lifetime.

This change removes manually constructed token and introspection URLs while preserving explicit OCI- and application-specific configuration that OpenID discovery cannot supply.

## Goals

- Fetch `{identity_domain_url}/.well-known/openid-configuration` once when constructing a `TokenFactory`.
- Derive the Identity Domain token endpoint, introspection endpoint, validation issuer, and JWKS URI from discovery metadata.
- Make construction fail clearly when discovery is unavailable or incomplete.
- Keep one internally consistent metadata snapshot for the factory lifetime.
- Preserve the distinction between the Identity Domain validation issuer and the OAuth application's assertion issuer.
- Keep Terraform inputs and outputs stable.

## Non-Goals

- Deriving the Identity Domain home region from OIDC metadata.
- Deriving the OCI workload/resource region from OIDC metadata.
- Deriving an OAuth application's assertion issuer from OIDC metadata.
- Refreshing discovery metadata in a running factory.
- Using discovery fields that Token Factory does not consume.
- Changing the current KMS, Vault, workload identity, or IAM policy contracts.

## Configuration Contract

The following values remain explicit:

- `identity_domain_url` / `TF_SHARED_DOMAIN_URL`: Identity Domain base URL and the source used to construct the discovery URL.
- `domain_region` / `TF_SHARED_DOMAIN_REGION`: Identity Domain home region used for OCI Identity Data Plane and token-exchange signer operations.
- `oci_region` / `TF_SHARED_OCI_REGION`: OCI workload/resource region used by other OCI SDK clients.
- OAuth app `issuer` / `TF_CLIENT_ISSUER`: Application-specific `iss` value for JWT assertions signed by the hosting application.

The following values become discovery-only runtime values:

- `issuer`: trusted issuer for validating Identity Domain JWTs.
- `jwks_uri`: key set used to validate Identity Domain JWT signatures.
- `token_endpoint`: endpoint for OAuth grants and token exchanges.
- `introspection_endpoint`: endpoint for opaque-token validation and hybrid validation.

Callers will not configure overrides for these discovered values.

## Metadata Model

Add an immutable internal `IdentityDomainMetadata` value object with:

- `issuer`
- `jwks_uri`
- `token_endpoint`
- `introspection_endpoint`

The object represents one validated discovery snapshot. It is not part of Terraform output and is not accepted as public runtime configuration.

## Construction and Data Flow

1. Normalize `identity_domain_url` by removing its trailing slash.
2. Construct `{identity_domain_url}/.well-known/openid-configuration`.
3. Fetch that URL through the existing injectable validation HTTP session with the configured timeout.
4. Require a successful HTTP response and a JSON object.
5. Extract and validate the four required metadata fields.
6. Store the resulting immutable metadata object on the factory.
7. Construct the default hybrid token validator from that same snapshot.
8. Reuse the snapshot for all OAuth exchanges and token validations performed by the factory.

Discovery occurs even when a custom token validator is injected because OAuth flows still require the discovered token endpoint. A factory that cannot complete discovery is not usable and will not be constructed.

## Endpoint Consumers

- Client-credentials exchange uses `IdentityDomainMetadata.token_endpoint`.
- JWT-bearer assertion exchange uses `IdentityDomainMetadata.token_endpoint`.
- OCI-credential token exchange uses `IdentityDomainMetadata.token_endpoint`.
- Identity-propagation exchange uses `IdentityDomainMetadata.token_endpoint`.
- Opaque-token introspection uses `IdentityDomainMetadata.introspection_endpoint`.
- JWT validation trusts only `IdentityDomainMetadata.issuer` and resolves keys from `IdentityDomainMetadata.jwks_uri`.

No runtime code will construct `/oauth2/v1/token` or `/oauth2/v1/introspect` paths directly.

## Issuer Separation

Identity Domain discovery metadata and OAuth app configuration describe different issuers:

- The discovered issuer identifies Identity Domain tokens accepted from callers.
- The configured app issuer is placed in the `iss` claim of assertions produced by the hosting OAuth application.

Discovery must not overwrite, default, or validate the app assertion issuer. Assertion-backed flows continue to require the app issuer explicitly.

## Validation and Security

Construction raises `ConfigurationError` when:

- the discovery request fails;
- the response is unsuccessful;
- the response is not a JSON object;
- any required field is absent or empty; or
- any discovered endpoint URL is not an absolute HTTPS URL.

The discovered issuer must be a non-empty absolute HTTPS URL. It is not required to share the configured base URL's host because OCI Identity Domains can publish a common issuer distinct from the tenant-specific endpoint host.

Error messages will identify the discovery URL and failure category without including response bodies, credentials, access tokens, or assertions.

## Lifecycle and Caching

Discovery is performed exactly once per factory construction. The immutable snapshot is retained for the lifetime of that factory and has no time-based refresh.

Deployments pick up endpoint or signing-metadata changes by constructing a new factory, which matches the existing deployment model of one long-lived factory per workload application.

## Terraform Impact

Terraform continues to accept and emit:

- `identity_domain_url`
- `identity_domain_region`
- top-level OCI `region`
- per-app assertion `issuer`

No Terraform HTTP data source or discovery-derived output is added. Terraform remains responsible for deployment resources and runtime configuration inputs; the Python runtime owns live OIDC discovery.

## Compatibility and Migration

Environment variable names remain unchanged. Existing deployments only need network access from the runtime to the public discovery URL.

Internally, token and introspection endpoint construction is replaced with metadata lookup. Tests or integrations that inject HTTP sessions must return discovery metadata during factory construction.

## Testing

Python tests will verify:

- the exact discovery URL and configured timeout;
- one discovery request per factory, including multiple token operations;
- use of the discovered token endpoint by every OAuth exchange path;
- use of the discovered introspection endpoint;
- use of the discovered issuer and JWKS URI for JWT validation;
- preservation of the explicit app assertion issuer;
- failures for network errors, unsuccessful responses, non-object JSON, missing fields, empty fields, non-absolute URLs, and non-HTTPS URLs;
- custom token-validator injection still performs discovery once;
- runtime code contains no hard-coded token or introspection endpoint paths.

Terraform tests will confirm that the current input/output contract remains unchanged.

## Acceptance Criteria

- A newly constructed factory performs one successful discovery request and stores one immutable metadata snapshot.
- All runtime Identity Domain OAuth/OIDC endpoint use comes from that snapshot.
- Identity Domain JWT trust comes from the discovered issuer and JWKS URI.
- Hosting assertions retain the explicitly configured app issuer.
- `domain_region` and `oci_region` remain explicit and semantically separate.
- Terraform contracts remain stable.
- Python and Terraform regression suites pass.
