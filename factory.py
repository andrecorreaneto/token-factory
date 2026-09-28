"""TokenFactory facade for converting caller or OCI credentials into downstream tokens."""

import base64
import hashlib
import json
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ._authorization import (
    AuthorizationPolicyProvider,
    AuthorizationRequest,
    GroupScopeAuthorizer,
    SignedVaultAuthorizationPolicyProvider,
    StaticAuthorizationPolicyProvider,
    VaultJsonAuthorizationPolicyProvider,
)
from ._errors import CallerAssertionValidationError, OAuthClientResolutionError
from ._identity_domain_discovery import IdentityDomainMetadata, discover_identity_domain_metadata
from ._factory_support import (
    ConfigurationError,
    DiscoveredTokenExchangeSigner,
    KmsJwtSigner,
    LOGGER,
    OCI_IDENTITY_AUDIENCE,
    SUPPORTED_TOKEN_TYPES,
    TokenExchangeError,
    _extract_token_exchange_signer_keypair_pem,
    _fetch_secret_value_from_oci,
    _generate_db_token_with_dataplane,
    _get_factory_oci_signer,
    build_oci_request_signer,
    build_signer_credential_from_profile,
)
from ._normalization import normalize_scopes
from ._oauth_client_resolution import (
    OAuthClientInfo,
    OAuthClientResolver,
    ResolvedHostingComponent,
    StaticOAuthClientResolver,
    VaultOAuthClientResolver,
)
from ._runtime_config import TokenFactoryRuntimeConfig
from ._token_validation import HybridTokenValidator


Credential = Optional[Union[str, Dict[str, Any]]]
ORACLE_DATABASE_CREDENTIAL_OCI_PRINCIPAL = "OCI_PRINCIPAL"
ORACLE_DATABASE_CREDENTIAL_PROCESS = "PROCESS"
_ORACLE_DATABASE_CREDENTIAL_SELECTORS = {
    ORACLE_DATABASE_CREDENTIAL_OCI_PRINCIPAL,
    ORACLE_DATABASE_CREDENTIAL_PROCESS,
}


@dataclass(frozen=True)
class CallerContext:
    """Validated caller data used by assertion-backed token flows."""

    hosting_component: ResolvedHostingComponent
    validated_assertion: Any
    subject: str
    groups: list[str]


class OracleDatabaseTokenResult(tuple):
    """Tuple-compatible Oracle Database token result with lifecycle attributes."""

    def __new__(cls, db_token: str, private_key_pem: str, expires_in: int, token_type: str, issued_token_type: str, *, principal_mode: str, expires_at_epoch: int):
        value = tuple.__new__(
            cls,
            (db_token, private_key_pem, expires_in, token_type, issued_token_type),
        )
        value.token = db_token
        value.db_token = db_token
        value.private_key_pem = private_key_pem
        value.expires_in = expires_in
        value.token_type = token_type
        value.issued_token_type = issued_token_type
        value.principal_mode = principal_mode
        value.expires_at_epoch = expires_at_epoch
        return value


@dataclass(frozen=True)
class TokenCacheEntry:
    """Cached TokenFactory result and its absolute expiration time."""

    result: Any
    expires_at_epoch: int


class TokenResultCache:
    """Thread-safe in-memory cache for reusable TokenFactory results."""

    def __init__(self, max_size: int = 1024):
        self._entries: OrderedDict[str, TokenCacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._max_size = max(1, int(max_size))

    def get(self, key: str, now: int, skew_seconds: int, label: str) -> Any | None:
        """Return a cached result when it remains valid after the safety skew."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                LOGGER.info("TokenFactory cache miss label=%s reason=absent key=%s", label, _cache_key_hint(key))
                return None
            if entry.expires_at_epoch <= now + skew_seconds:
                self._entries.pop(key, None)
                LOGGER.info("TokenFactory cache miss label=%s reason=expired key=%s", label, _cache_key_hint(key))
                return None
            self._entries.move_to_end(key)
            LOGGER.info("TokenFactory cache hit label=%s key=%s expires_in_seconds=%s", label, _cache_key_hint(key), entry.expires_at_epoch - now)
            return _copy_cached_result(entry.result)

    def set(self, key: str, result: Any, expires_at_epoch: int, now: int, skew_seconds: int) -> Any:
        """Store a result if it has a reusable lifetime."""
        if expires_at_epoch <= now + skew_seconds:
            return result
        with self._lock:
            self._entries[key] = TokenCacheEntry(_copy_cached_result(result), expires_at_epoch)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_size:
                evicted_key, _entry = self._entries.popitem(last=False)
                LOGGER.info("TokenFactory cache eviction reason=max_size key=%s max_size=%s", _cache_key_hint(evicted_key), self._max_size)
        return result

    def clear(self) -> None:
        """Remove every cached result."""
        with self._lock:
            self._entries.clear()


class TokenFactory:
    """Exchanges caller or OCI credentials for documented downstream token shapes."""

    def __init__(self, config_overrides: Optional[Dict[str, Any]] = None, *, runtime_config: Optional[Union[TokenFactoryRuntimeConfig, Dict[str, Any]]] = None, oauth_apps: Optional[Dict[str, Union[Dict[str, Any], OAuthClientInfo]]] = None, oauth_client_resolver: Optional[OAuthClientResolver] = None, authorization_policy_provider: Optional[AuthorizationPolicyProvider] = None, authorizer: Optional[GroupScopeAuthorizer] = None, token_endpoint_session: Any = requests, token_validation_session: Any = requests, token_validator: Any = None, token_exchange_signer_cls: Any = DiscoveredTokenExchangeSigner, signer_keypair_extractor: Any = _extract_token_exchange_signer_keypair_pem, db_token_generator: Any = _generate_db_token_with_dataplane, factory_oci_signer_builder: Any = _get_factory_oci_signer, oci_signer_builder: Any = build_oci_request_signer, jwt_assertion_signer: Any = None, token_cache_enabled: Optional[bool] = None, token_cache: Optional[TokenResultCache] = None, token_cache_skew_seconds: int = 5, token_cache_max_size: Optional[int] = None):
        """Configure runtime settings, OAuth client resolution, authorization, and exchange clients."""
        if config_overrides is not None and not isinstance(config_overrides, dict):
            raise TypeError("TokenFactory expects no positional argument or a config overrides dict.")
        if oauth_apps is not None and oauth_client_resolver is not None:
            raise ValueError("Pass either oauth_apps or oauth_client_resolver, not both.")

        if isinstance(runtime_config, dict):
            runtime_config = TokenFactoryRuntimeConfig(**runtime_config)
        if runtime_config is None:
            runtime_config = TokenFactoryRuntimeConfig.from_env(config_overrides)

        self._runtime_config = runtime_config
        self._identity_domain_metadata = discover_identity_domain_metadata(runtime_config.domain_url, runtime_config.timeout_seconds, token_validation_session)
        self._authz_policy_enable = runtime_config.authz_policy_enable
        self._oauth_client_resolver = oauth_client_resolver or _resolver_from_oauth_apps(
            oauth_apps,
            runtime_config,
        )
        policy_provider = authorization_policy_provider or _default_policy_provider(runtime_config)
        self._authorizer = authorizer or GroupScopeAuthorizer(policy_provider)
        self._token_endpoint_session = token_endpoint_session
        self._token_validation_session = token_validation_session
        self._token_validator = token_validator
        self._token_exchange_signer_cls = token_exchange_signer_cls
        self._signer_keypair_extractor = signer_keypair_extractor
        self._db_token_generator = db_token_generator
        self._factory_oci_signer_builder = factory_oci_signer_builder
        self._oci_signer_builder = oci_signer_builder
        self._jwt_assertion_signer = jwt_assertion_signer
        self._token_cache_enabled = runtime_config.cache_enable if token_cache_enabled is None else bool(token_cache_enabled)
        resolved_cache_max_size = runtime_config.cache_max_size if token_cache_max_size is None else token_cache_max_size
        self._token_cache = token_cache or TokenResultCache(resolved_cache_max_size)
        self._token_cache_skew_seconds = max(0, int(token_cache_skew_seconds))

    @classmethod
    def from_env(cls, config_overrides: Optional[Dict[str, Any]] = None) -> "TokenFactory":
        """Build a TokenFactory from process environment and optional overrides."""
        return cls(config_overrides)

    def get_token(self, credential: Credential, token_type: str, scope: Optional[str] = None, *, client_key: Optional[str] = None) -> Any:
        """Exchange a caller credential for the requested documented token type."""
        credential, token_type = _normalize_get_token_arguments(credential, token_type)
        if token_type not in SUPPORTED_TOKEN_TYPES:
            supported = ", ".join(SUPPORTED_TOKEN_TYPES)
            raise ValueError(f"Unsupported token_type '{token_type}'. Supported values: {supported}")

        resolved_client_key = _require_client_key(client_key)
        if token_type == "oauth":
            return self._get_oauth_token(credential, scope, resolved_client_key)
        if token_type == "oracle-database":
            return self._get_oracle_database_token(credential, scope, resolved_client_key)
        if token_type == "userid":
            return self._get_userid_token(credential, resolved_client_key)
        return self._get_oci_service_token(credential, resolved_client_key)

    def get_token_with_oci_credential(self, credential: Credential, scope: Optional[str] = None) -> Dict[str, Any]:
        """Exchange an OCI signer dictionary or profile name for an OAuth token."""
        cache_key = _cache_key("oci-credential-oauth", scope or "", _oci_credential_cache_identity(credential))
        cached = self._get_cached_result(cache_key, "oci-credential-oauth")
        if cached is not None:
            return cached

        signer_credential = self._resolve_oci_credential(credential)
        signer = self._oci_signer_builder(signer_credential)
        endpoint = self._identity_domain_metadata.token_endpoint
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if scope:
            request_data["scope"] = scope

        response = self._token_endpoint_session.post(
            endpoint,
            data=urlencode(request_data),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            auth=signer,
            timeout=self._runtime_config.timeout_seconds,
        )
        return self._cache_result(cache_key, _oauth_result(_response_payload_or_raise(response, "OCI credential OAuth exchange")))

    def clear_token_cache(self) -> None:
        """Remove cached TokenFactory results for this instance."""
        self._token_cache.clear()

    def _get_oauth_token(self, credential: Credential, scope: Optional[str], client_key: str) -> Dict[str, Any]:
        requested_scope = _require_scope(scope, "oauth")
        if credential is None:
            hosting_component = self._resolve_hosting_component(
                client_key,
                require_signing_material=False,
            )
            cache_key = _cache_key("oauth-client-credentials", client_key, requested_scope)
            cached = self._get_cached_result(cache_key, "oauth-client-credentials")
            if cached is not None:
                return cached
            return self._cache_result(cache_key, self._exchange_client_credentials_for_oauth(requested_scope, hosting_component))

        assertion = _require_caller_assertion(credential, "oauth")
        context = self._validate_assertion(assertion, client_key)
        issued_scope = _issued_scope_for_pass_through(requested_scope)
        self._authorize(context, "oauth", requested_scope)
        if _validated_token_can_be_passed_through(context, issued_scope, requested_scope):
            return _incoming_oauth_result(assertion)

        cache_key = _cache_key("oauth-assertion", client_key, requested_scope, _secret_fingerprint(assertion))
        cached = self._get_cached_result(cache_key, "oauth-assertion")
        if cached is not None:
            return cached

        jwt_assertion = self._build_jwt_assertion(context.subject, context.hosting_component, "oauth")
        return self._cache_result(cache_key, self._exchange_assertion_for_oauth(jwt_assertion, requested_scope, context.hosting_component), assertion)

    def _get_oracle_database_token(self, credential: Credential, scope: Optional[str], client_key: str) -> OracleDatabaseTokenResult:
        requested_scope = _require_scope(scope, "oracle-database")
        selector = _oracle_database_credential_selector(credential)
        if selector == ORACLE_DATABASE_CREDENTIAL_OCI_PRINCIPAL:
            cache_key = _cache_key("oracle-database-oci-principal", requested_scope, self._runtime_config.oci_auth_mode, self._runtime_config.domain_url, self._runtime_config.domain_region)
            cached = self._get_cached_result(cache_key, "oracle-database-oci-principal")
            if cached is not None:
                return cached
            return self._cache_result(cache_key, self._exchange_oracle_database_token_with_oci_principal(requested_scope))
        if selector == ORACLE_DATABASE_CREDENTIAL_PROCESS:
            raise NotImplementedError(
                "oracle-database credential selector 'PROCESS' is reserved for future RPST process-principal support and is not implemented yet."
            )

        assertion = _require_caller_assertion(credential, "oracle-database")
        context = self._validate_assertion(assertion, client_key)
        self._authorize(context, "oracle-database", requested_scope)
        cache_key = _cache_key("oracle-database-assertion", client_key, requested_scope, _secret_fingerprint(assertion))
        cached = self._get_cached_result(cache_key, "oracle-database-assertion")
        if cached is not None:
            return cached
        return self._cache_result(cache_key, self._exchange_oracle_database_token(context.subject, context.hosting_component, requested_scope), assertion)

    def _get_userid_token(self, credential: Credential, client_key: str) -> Dict[str, Any]:
        assertion = _require_caller_assertion(credential, "userid")
        context = self._validate_assertion(assertion, client_key)
        return {"issued_token_type": "userid", "user_id": context.subject}

    def _get_oci_service_token(self, credential: Credential, client_key: str) -> Any:
        assertion = _require_caller_assertion(credential, "oci-service")
        context = self._validate_assertion(assertion, client_key)
        cache_key = _cache_key("oci-service", client_key, _secret_fingerprint(assertion))
        cached = self._get_cached_result(cache_key, "oci-service")
        if cached is not None:
            return cached
        return self._cache_result(cache_key, self._exchange_oci_service_token(context.subject, context.hosting_component), assertion, max_expires_at_epoch=int(time.time()) + 300)

    def _get_cached_result(self, cache_key: str, cache_label: str) -> Any | None:
        """Return a cached result when cache is enabled and the entry is valid."""
        if not self._token_cache_enabled:
            return None
        return self._token_cache.get(cache_key, int(time.time()), self._token_cache_skew_seconds, cache_label)

    def _cache_result(self, cache_key: str, result: Any, caller_assertion: Optional[str] = None, *, max_expires_at_epoch: Optional[int] = None) -> Any:
        """Cache a result when cache is enabled and a reliable expiration is available."""
        if not self._token_cache_enabled:
            return result
        expires_at_epoch = _result_expires_at_epoch(result)
        if expires_at_epoch <= 0 and max_expires_at_epoch is not None:
            expires_at_epoch = max_expires_at_epoch
        if caller_assertion:
            caller_expires_at_epoch = _expires_at_epoch(caller_assertion)
            expires_at_epoch = min(expires_at_epoch, caller_expires_at_epoch) if expires_at_epoch > 0 else caller_expires_at_epoch
        if max_expires_at_epoch is not None:
            expires_at_epoch = min(expires_at_epoch, max_expires_at_epoch)
        return self._token_cache.set(cache_key, result, expires_at_epoch, int(time.time()), self._token_cache_skew_seconds)

    def _validate_assertion(self, credential: str, client_key: str) -> CallerContext:
        hosting_component = self._resolve_hosting_component(client_key, require_signing_material=self._jwt_assertion_signer is None)
        validated = self._get_token_validator().validate(credential, hosting_component)
        subject = validated.claims.get(self._runtime_config.subject_claim)
        if not subject:
            raise CallerAssertionValidationError(
                f"Validated caller assertion is missing subject claim '{self._runtime_config.subject_claim}'."
            )
        return CallerContext(
            hosting_component=hosting_component,
            validated_assertion=validated,
            subject=str(subject),
            groups=normalize_scopes(validated.claims.get(self._runtime_config.groups_claim, [])),
        )

    def _get_token_validator(self) -> Any:
        if self._token_validator is None:
            claim_overrides = [self._runtime_config.groups_claim or "groups"]
            self._token_validator = _default_token_validator(
                self._runtime_config,
                claim_overrides,
                self._identity_domain_metadata,
                self._token_validation_session,
            )
        return self._token_validator

    def _resolve_hosting_component(self, client_key: str, *, require_signing_material: bool = True) -> ResolvedHostingComponent:
        if self._oauth_client_resolver is None:
            raise OAuthClientResolutionError("TokenFactory.get_token requires oauth_apps or oauth_client_resolver.")
        return self._oauth_client_resolver.resolve(
            client_key,
            require_signing_material=require_signing_material,
        )

    def _authorize(self, context: CallerContext, token_type: str, scope: str) -> None:
        if not self._authz_policy_enable:
            return
        self._authorizer.authorize(
            AuthorizationRequest(
                subject=context.subject,
                groups=context.groups,
                token_type=token_type,
                scope=scope,
            )
        )

    def _build_jwt_assertion(self, subject: str, hosting_component: ResolvedHostingComponent, token_type: str) -> str:
        identity = hosting_component.oauth_identity
        if not identity.issuer:
            raise OAuthClientResolutionError(f"OAuth client '{hosting_component.client_key}' is missing issuer.")
        issuer = identity.issuer
        now = int(time.time())
        payload = {
            "iss": issuer,
            "sub": subject,
            "aud": _jwt_audience(self._identity_domain_metadata, token_type),
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        }
        payload.update(_propagation_trust_claim(hosting_component, token_type))
        headers = {"alg": "RS256", "typ": "JWT"}
        if identity.kid:
            headers["kid"] = identity.kid

        if self._jwt_assertion_signer is not None:
            return _sign_compact_jws(headers, payload, self._jwt_assertion_signer)
        if not identity.kms_key_id or not identity.kms_key_version_id or not identity.kms_crypto_endpoint:
            raise OAuthClientResolutionError(f"OAuth client '{hosting_component.client_key}' requires KMS key ID, key version ID, and cryptographic endpoint.")
        return _sign_compact_jws(headers, payload, KmsJwtSigner(identity.kms_key_id, identity.kms_key_version_id, identity.kms_crypto_endpoint, self._factory_oci_signer_builder, self._runtime_config))

    def _exchange_assertion_for_oauth(self, assertion: str, scope: Optional[str], hosting_component: ResolvedHostingComponent) -> Dict[str, Any]:
        identity = hosting_component.oauth_identity
        credentials = base64.b64encode(f"{identity.client_id}:{identity.client_secret}".encode("utf-8")).decode("utf-8")
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        if scope:
            request_data["scope"] = scope

        response = self._token_endpoint_session.post(
            self._identity_domain_metadata.token_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {credentials}",
            },
            data=request_data,
            timeout=self._runtime_config.timeout_seconds,
        )
        return _oauth_result(_response_payload_or_raise(response, "OAuth exchange"))

    def _exchange_client_credentials_for_oauth(self, scope: Optional[str], hosting_component: ResolvedHostingComponent) -> Dict[str, Any]:
        identity = hosting_component.oauth_identity
        credentials = base64.b64encode(f"{identity.client_id}:{identity.client_secret}".encode("utf-8")).decode("utf-8")
        request_data = {"grant_type": "client_credentials"}
        if scope:
            request_data["scope"] = scope

        response = self._token_endpoint_session.post(
            self._identity_domain_metadata.token_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {credentials}",
            },
            data=request_data,
            timeout=self._runtime_config.timeout_seconds,
        )
        return _oauth_result(_response_payload_or_raise(response, "OAuth client credentials exchange"))

    def _exchange_oci_service_token(self, subject: str, hosting_component: ResolvedHostingComponent) -> Any:
        assertion = self._build_jwt_assertion(subject, hosting_component, "oci-service")
        return self._build_upst_signer(assertion, hosting_component)

    def _exchange_oracle_database_token(self, subject: str, hosting_component: ResolvedHostingComponent, scope: str) -> OracleDatabaseTokenResult:
        assertion = self._build_jwt_assertion(subject, hosting_component, "oracle-database")
        signer = self._build_upst_signer(assertion, hosting_component)
        public_key_pem, private_key_pem = self._signer_keypair_extractor(signer)
        db_token = self._db_token_generator(signer, public_key_pem, scope, self._runtime_config)
        return _oracle_database_token_result(db_token, private_key_pem, principal_mode="user")

    def _exchange_oracle_database_token_with_oci_principal(self, scope: str) -> OracleDatabaseTokenResult:
        signer = self._factory_oci_signer_builder(self._runtime_config)
        public_key_pem, private_key_pem = _generate_database_session_keypair_pem()
        db_token = self._db_token_generator(signer, public_key_pem, scope, self._runtime_config)
        return _oracle_database_token_result(db_token, private_key_pem, principal_mode="oci_principal")

    def _build_upst_signer(self, assertion: str, hosting_component: ResolvedHostingComponent) -> Any:
        identity = hosting_component.oauth_identity
        return self._token_exchange_signer_cls(
            assertion,
            self._identity_domain_metadata.token_endpoint,
            identity.client_id,
            identity.client_secret,
            region=self._runtime_config.domain_region,
        )

    @staticmethod
    def _resolve_oci_credential(credential: Credential) -> Dict[str, Any]:
        if isinstance(credential, dict):
            return credential
        if isinstance(credential, str) and credential:
            return build_signer_credential_from_profile(credential)
        raise ValueError("OCI credential must be a signer dictionary or OCI profile name.")


def _resolver_from_oauth_apps(oauth_apps: Optional[Dict[str, Union[Dict[str, Any], OAuthClientInfo]]], runtime_config: TokenFactoryRuntimeConfig) -> Optional[OAuthClientResolver]:
    if oauth_apps is None:
        return None
    if not oauth_apps:
        raise ValueError("oauth_apps must contain at least one OAuth app.")

    client_info = {
        client_key: _coerce_oauth_client_info(client_key, info)
        for client_key, info in oauth_apps.items()
    }
    if any(_oauth_app_uses_vault(info) for info in client_info.values()):
        return VaultOAuthClientResolver(client_info, runtime_config=runtime_config)
    return StaticOAuthClientResolver(client_info)


def _coerce_oauth_client_info(client_key: str, value: Union[Dict[str, Any], OAuthClientInfo]) -> OAuthClientInfo:
    if not isinstance(client_key, str) or not client_key.strip():
        raise ValueError("oauth_apps keys must be non-empty strings.")
    if isinstance(value, OAuthClientInfo):
        return value
    if not isinstance(value, dict):
        raise ValueError(f"oauth_apps['{client_key}'] must be a dict or OAuthClientInfo.")
    try:
        return OAuthClientInfo(**value)
    except TypeError as exc:
        raise ValueError(f"oauth_apps['{client_key}'] contains unsupported fields: {exc}") from exc


def _oauth_app_uses_vault(info: OAuthClientInfo) -> bool:
    return any(
        [
            info.client_credentials_secret_ocid,
        ]
    )


def _require_client_key(client_key: Optional[str]) -> str:
    if not isinstance(client_key, str):
        raise OAuthClientResolutionError("client_key is required.")
    stripped = client_key.strip()
    if not stripped:
        raise OAuthClientResolutionError("client_key is required.")
    return stripped


def _require_scope(scope: Optional[str], token_type: str) -> str:
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError(f"Scope is required for token_type '{token_type}'")
    return scope.strip()


def _require_caller_assertion(credential: Credential, token_type: str) -> str:
    if not isinstance(credential, str) or not credential:
        raise ValueError(f"token_type '{token_type}' requires credential to be a non-empty caller assertion string.")
    return credential


def _normalize_get_token_arguments(credential: Credential, token_type: str) -> Tuple[Credential, str]:
    if isinstance(credential, str) and credential in SUPPORTED_TOKEN_TYPES:
        if not isinstance(token_type, str) or token_type not in SUPPORTED_TOKEN_TYPES:
            return token_type, credential
    return credential, token_type


def _oracle_database_credential_selector(credential: Credential) -> Optional[str]:
    if not isinstance(credential, str):
        return None
    normalized = credential.strip().upper()
    if normalized in _ORACLE_DATABASE_CREDENTIAL_SELECTORS:
        return normalized
    return None


def _generate_database_session_keypair_pem() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return public_key_pem, private_key_pem


def _oracle_database_token_result(db_token: str, private_key_pem: str, *, principal_mode: str) -> OracleDatabaseTokenResult:
    expires_at_epoch = _expires_at_epoch(db_token)
    return OracleDatabaseTokenResult(
        db_token,
        private_key_pem,
        max(expires_at_epoch - int(time.time()), 0),
        "Bearer",
        "oracle-database",
        principal_mode=principal_mode,
        expires_at_epoch=expires_at_epoch,
    )


def _default_policy_provider(runtime_config: TokenFactoryRuntimeConfig) -> AuthorizationPolicyProvider:
    if not runtime_config.authz_policy_secret_ocid:
        return StaticAuthorizationPolicyProvider(None)

    def read_secret(secret_ocid: str) -> str:
        return _fetch_secret_value_from_oci(secret_ocid, runtime_config.oci_region, runtime_config)

    if runtime_config.authz_policy_signature_mode == "on":
        return SignedVaultAuthorizationPolicyProvider(
            runtime_config.authz_policy_secret_ocid,
            read_secret,
            trusted_signers=runtime_config.authz_trusted_signers or [],
            expected_domain_url=runtime_config.domain_url,
            expected_environment=runtime_config.authz_policy_environment,
            expected_tenant_id=runtime_config.authz_policy_tenant_id,
        )
    return VaultJsonAuthorizationPolicyProvider(runtime_config.authz_policy_secret_ocid, read_secret)


def _default_token_validator(runtime_config: TokenFactoryRuntimeConfig, claim_overrides: list[str], metadata: IdentityDomainMetadata, session: Any = requests) -> Any:
    trusted_issuers = _trusted_issuers_from_metadata(metadata, claim_overrides)
    return HybridTokenValidator(
        introspection_endpoint=metadata.introspection_endpoint,
        trusted_issuers=trusted_issuers,
        jwt_claim_overrides=claim_overrides,
        timeout_seconds=runtime_config.timeout_seconds,
        session=session,
    )


def _trusted_issuers_from_metadata(metadata: IdentityDomainMetadata, required_claims: list[str]) -> Dict[str, Dict[str, Any]]:
    return {
        metadata.issuer: {
            "jwks_url": metadata.jwks_uri,
            "algorithms": ["RS256"],
            "required_claims": required_claims,
        }
    }


def _response_payload_or_raise(response: Any, label: str) -> Dict[str, Any]:
    if not getattr(response, "ok", False):
        raise TokenExchangeError(
            f"{label} failed [{getattr(response, 'status_code', 'unknown')}]: {getattr(response, 'text', '')}"
        )
    data = response.json()
    access_token = data.get("access_token") or data.get("token")
    if not access_token:
        raise TokenExchangeError(f"{label} response missing access_token")
    data["access_token"] = access_token
    return data


def _oauth_result(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "token": data["access_token"],
        "access_token": data["access_token"],
        "expires_in": data.get("expires_in"),
        "token_type": data.get("token_type", "Bearer"),
        "issued_token_type": "oauth",
    }


def _copy_cached_result(result: Any) -> Any:
    """Return a caller-safe copy for mutable cached result shapes."""
    if isinstance(result, dict):
        return dict(result)
    return result


def _cache_key(*parts: Any) -> str:
    """Build a deterministic cache key from non-secret or pre-fingerprinted parts."""
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _sign_compact_jws(headers: Dict[str, Any], payload: Dict[str, Any], signer: Any) -> str:
    """Build an RS256 compact JWS with a signature produced outside the process."""
    encoded_header = _base64url_json(headers)
    encoded_payload = _base64url_json(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = signer.sign(signing_input)
    if not isinstance(signature, bytes):
        raise TokenExchangeError("JWT signer must return signature bytes.")
    return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"


def _base64url_json(value: Dict[str, Any]) -> str:
    return _base64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _cache_key_hint(key: str) -> str:
    """Return a short non-secret cache key hint for logs."""
    return key[:12]


def _secret_fingerprint(value: str) -> str:
    """Hash a sensitive string before using it as a cache-key dimension."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _credential_fingerprint(credential: Any) -> str:
    """Hash an OCI credential shape before using it as a cache-key dimension."""
    serialized = json.dumps(credential, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _oci_credential_cache_identity(credential: Credential) -> str:
    """Return a stable fingerprint for an OCI signer dictionary or profile name."""
    if isinstance(credential, str):
        return _secret_fingerprint(f"profile:{credential}")
    return _credential_fingerprint(credential)


def _result_expires_at_epoch(result: Any) -> int:
    """Return a reliable absolute expiration time for cacheable result shapes."""
    if isinstance(result, OracleDatabaseTokenResult):
        return int(result.expires_at_epoch)
    if isinstance(result, dict):
        expires_in = result.get("expires_in")
        if expires_in is not None:
            try:
                return int(time.time()) + int(expires_in)
            except (TypeError, ValueError):
                pass
        access_token = result.get("access_token") or result.get("token")
        if isinstance(access_token, str) and access_token:
            return _jwt_expires_at_epoch(access_token)
    return 0


def _incoming_oauth_result(access_token: str) -> Dict[str, Any]:
    return {
        "token": access_token,
        "access_token": access_token,
        "expires_in": _expires_in(access_token),
        "token_type": "Bearer",
        "issued_token_type": "oauth",
        "source": "incoming_token",
    }


def _validated_token_can_be_passed_through(context: CallerContext, issued_scope: str, requested_scope: str) -> bool:
    return _validated_token_has_scope(context, issued_scope) and _validated_token_has_audience(
        context,
        _resource_audience_for_request_scope(requested_scope),
    )


def _validated_token_has_scope(context: CallerContext, scope: str) -> bool:
    incoming_scopes = getattr(context.validated_assertion, "incoming_scopes", None)
    if not incoming_scopes:
        return False
    return scope in set(incoming_scopes)


def _validated_token_has_audience(context: CallerContext, audience: Optional[str]) -> bool:
    if audience is None:
        return True
    token_audience = getattr(context.validated_assertion, "audience", None)
    if isinstance(token_audience, str):
        values = {token_audience}
    elif isinstance(token_audience, (list, tuple, set)):
        values = {str(item) for item in token_audience}
    else:
        values = set()
    return audience in values


def _issued_scope_for_pass_through(scope: str) -> str:
    parsed = urlsplit(scope)
    if parsed.scheme and parsed.netloc and parsed.path:
        return parsed.path.lstrip("/")
    return scope


def _resource_audience_for_request_scope(scope: str) -> Optional[str]:
    parsed = urlsplit(scope)
    if parsed.scheme and parsed.netloc and parsed.path:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return None


def _jwt_audience(metadata: IdentityDomainMetadata, token_type: str) -> str:
    if token_type in {"oracle-database", "oci-service"}:
        return metadata.token_endpoint
    return OCI_IDENTITY_AUDIENCE


def _propagation_trust_claim(hosting_component: ResolvedHostingComponent, token_type: str) -> Dict[str, str]:
    if token_type not in {"oracle-database", "oci-service"}:
        return {}
    if not hosting_component.propagation_trust_claim:
        return {}
    claim_name, separator, claim_value = hosting_component.propagation_trust_claim.partition(":")
    if separator != ":" or not claim_name.strip() or not claim_value.strip():
        raise ConfigurationError("TF_CLIENT_PROPAGATION_TRUST_CLAIM must be formatted as claim_name:claim_value")
    return {claim_name.strip(): claim_value.strip()}


def _expires_in(token: str) -> int:
    return max(_expires_at_epoch(token) - int(time.time()), 0)


def _expires_at_epoch(token: str) -> int:
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        expires_at = int(payload.get("exp", 0))
        if expires_at > 0:
            return expires_at
    except Exception:
        pass
    return int(time.time()) + 3600


def _jwt_expires_at_epoch(token: str) -> int:
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        expires_at = int(payload.get("exp", 0))
        if expires_at > 0:
            return expires_at
    except Exception:
        pass
    return 0
