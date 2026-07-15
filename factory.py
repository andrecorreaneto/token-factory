import base64
import time
import uuid
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlsplit
from urllib.parse import urlencode

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from oci.auth.signers import TokenExchangeSigner

from ._authorization import (
    AuthorizationPolicyProvider,
    AuthorizationRequest,
    GroupScopeAuthorizer,
    SignedVaultAuthorizationPolicyProvider,
    StaticAuthorizationPolicyProvider,
    VaultJsonAuthorizationPolicyProvider,
)
from ._errors import CallerAssertionValidationError
from ._errors import OAuthClientResolutionError
from ._factory_support import (
    ConfigurationError,
    LOGGER,
    OCI_IDENTITY_AUDIENCE,
    SUPPORTED_TOKEN_TYPES,
    TokenExchangeError,
    TokenFactoryConfig,
    _extract_identity_domain_id,
    _extract_token_exchange_signer_keypair_pem,
    _fetch_secret_value_from_oci,
    _generate_db_token_with_dataplane,
    _get_factory_oci_signer,
    build_oci_request_signer,
    build_signer_credential_from_profile,
)
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


class OracleDatabaseTokenResult(tuple):
    def __new__(
        cls,
        db_token: str,
        private_key_pem: str,
        expires_in: int,
        token_type: str,
        issued_token_type: str,
        *,
        principal_mode: str,
        expires_at_epoch: int,
    ):
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


class TokenFactory:
    def __init__(
        self,
        config_or_overrides: Optional[Union[TokenFactoryConfig, Dict[str, Any]]] = None,
        *,
        config: Optional[TokenFactoryConfig] = None,
        runtime_config: Optional[Union[TokenFactoryRuntimeConfig, Dict[str, Any]]] = None,
        oauth_apps: Optional[Dict[str, Union[Dict[str, Any], OAuthClientInfo]]] = None,
        oauth_client_resolver: Optional[OAuthClientResolver] = None,
        authorization_policy_provider: Optional[AuthorizationPolicyProvider] = None,
        authorizer: Optional[GroupScopeAuthorizer] = None,
        token_endpoint_session: Any = requests,
        token_exchange_signer_cls: Any = TokenExchangeSigner,
        signer_keypair_extractor: Any = _extract_token_exchange_signer_keypair_pem,
        db_token_generator: Any = _generate_db_token_with_dataplane,
        factory_oci_signer_builder: Any = _get_factory_oci_signer,
        oci_signer_builder: Any = build_oci_request_signer,
    ):
        if config is not None and config_or_overrides is not None:
            raise ValueError("Pass either config_or_overrides or config, not both.")
        if oauth_apps is not None and oauth_client_resolver is not None:
            raise ValueError("Pass either oauth_apps or oauth_client_resolver, not both.")

        legacy_config = _resolve_legacy_config(config_or_overrides, config)
        if isinstance(runtime_config, dict):
            runtime_config = TokenFactoryRuntimeConfig(**runtime_config)
        if runtime_config is None:
            if legacy_config is not None:
                runtime_config = TokenFactoryRuntimeConfig.from_legacy_config(legacy_config)
            else:
                runtime_config = TokenFactoryRuntimeConfig.from_env(
                    config_or_overrides if isinstance(config_or_overrides, dict) else None
                )

        self._runtime_config = runtime_config
        self._authz_policy_enable = runtime_config.authz_policy_enable
        self._legacy_config = legacy_config
        self._oauth_client_resolver = (
            oauth_client_resolver
            or _resolver_from_oauth_apps(oauth_apps, runtime_config)
        )
        self._token_validator = _default_token_validator(runtime_config)
        policy_provider = authorization_policy_provider or _default_policy_provider(
            runtime_config,
            legacy_config,
        )
        self._authorizer = authorizer or GroupScopeAuthorizer(policy_provider)
        self._token_endpoint_session = token_endpoint_session
        self._token_exchange_signer_cls = token_exchange_signer_cls
        self._signer_keypair_extractor = signer_keypair_extractor
        self._db_token_generator = db_token_generator
        self._factory_oci_signer_builder = factory_oci_signer_builder
        self._oci_signer_builder = oci_signer_builder

    @classmethod
    def from_env(cls, config_overrides: Optional[Dict[str, Any]] = None) -> "TokenFactory":
        return cls(config_overrides)

    def get_token(
        self,
        credential: Credential,
        token_type: str,
        scope: Optional[str] = None,
        *,
        client_key: Optional[str] = None,
    ) -> Any:
        credential, token_type = _normalize_get_token_arguments(credential, token_type)
        if token_type not in SUPPORTED_TOKEN_TYPES:
            supported = ", ".join(SUPPORTED_TOKEN_TYPES)
            raise ValueError(
                f"Unsupported token_type '{token_type}'. Supported values: {supported}"
            )
        resolved_client_key = _require_client_key(client_key)
        if token_type == "oauth" and credential is None:
            if not scope:
                raise ValueError(f"Scope is required for token_type '{token_type}'")
            hosting_component = self._resolve_hosting_component(resolved_client_key)
            return self._exchange_client_credentials_for_oauth(
                scope,
                hosting_component,
            )
        if token_type == "oracle-database":
            if not scope:
                raise ValueError(f"Scope is required for token_type '{token_type}'")
            selector = _oracle_database_credential_selector(credential)
            if selector == ORACLE_DATABASE_CREDENTIAL_OCI_PRINCIPAL:
                _require_oci_principal_database_auth_mode(self._runtime_config)
                return self._exchange_oracle_database_token_with_oci_principal(scope)
            if selector == ORACLE_DATABASE_CREDENTIAL_PROCESS:
                raise NotImplementedError(
                    "oracle-database credential selector 'PROCESS' is reserved for "
                    "future RPST process-principal support and is not implemented yet."
                )
        if not isinstance(credential, str) or not credential:
            raise ValueError(
                f"token_type '{token_type}' requires credential to be a non-empty caller assertion string."
            )
        if token_type in {"oauth", "oracle-database"} and not scope:
            raise ValueError(f"Scope is required for token_type '{token_type}'")

        context = self._validate_assertion(credential, resolved_client_key)
        if token_type == "userid":
            return {"issued_token_type": "userid", "user_id": context["subject"]}
        if token_type == "oauth":
            issued_scope = _issued_scope_for_pass_through(scope or "")
            self._authorize(context, token_type, scope or "")
            if _validated_token_can_be_passed_through(context, issued_scope, scope or ""):
                return _incoming_oauth_result(credential)
            assertion = self._build_jwt_assertion(
                context["subject"],
                context["hosting_component"],
                "oauth",
            )
            return self._exchange_assertion_for_oauth(
                assertion,
                scope,
                context["hosting_component"],
            )
        if token_type == "oracle-database":
            self._authorize(context, token_type, scope or "")
            return self._exchange_oracle_database_token(
                context["subject"],
                context["hosting_component"],
                scope or "",
            )
        return self._exchange_oci_service_token(
            context["subject"],
            context["hosting_component"],
        )

    def get_token_with_oci_credential(
        self,
        credential: Credential,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        signer_credential = self._resolve_oci_credential(credential)
        signer = self._oci_signer_builder(signer_credential)
        endpoint = f"{self._runtime_config.domain_url}/oauth2/v1/token"
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
        data = _response_payload_or_raise(response, "OCI credential OAuth exchange")
        return _oauth_result(data)

    def _validate_assertion(
        self,
        credential: str,
        client_key: str,
    ) -> Dict[str, Any]:
        hosting_component = self._resolve_hosting_component(client_key)
        validated = self._token_validator.validate(credential, hosting_component)
        subject = validated.claims.get(self._runtime_config.subject_claim)
        if not subject:
            raise CallerAssertionValidationError(
                f"Validated caller assertion is missing subject claim '{self._runtime_config.subject_claim}'."
            )
        groups = _normalize_groups(validated.claims.get(self._runtime_config.groups_claim, []))
        return {
            "hosting_component": hosting_component,
            "validated_assertion": validated,
            "subject": str(subject),
            "groups": groups,
        }

    def _resolve_hosting_component(self, client_key: str) -> ResolvedHostingComponent:
        if self._oauth_client_resolver is None:
            raise OAuthClientResolutionError(
                "TokenFactory.get_token requires oauth_apps or oauth_client_resolver."
            )
        return self._oauth_client_resolver.resolve(client_key)

    def _authorize(self, context: Dict[str, Any], token_type: str, scope: str) -> None:
        if not self._authz_policy_enable:
            return
        self._authorizer.authorize(
            AuthorizationRequest(
                subject=context["subject"],
                groups=context["groups"],
                token_type=token_type,
                scope=scope,
            )
        )

    def _build_jwt_assertion(
        self,
        subject: str,
        hosting_component: ResolvedHostingComponent,
        token_type: str,
    ) -> str:
        now = int(time.time())
        identity = hosting_component.oauth_identity
        payload = {
            "iss": identity.issuer,
            "sub": subject,
            "aud": _jwt_audience(self._runtime_config, token_type),
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        }
        payload.update(_propagation_trust_claim(hosting_component, token_type))
        headers = {"typ": "JWT"}
        if identity.kid:
            headers["kid"] = identity.kid

        key = _load_private_key(identity.private_key_pem, identity.private_key_passphrase)
        return jwt.encode(payload, key=key, algorithm="RS256", headers=headers)

    def _exchange_assertion_for_oauth(
        self,
        assertion: str,
        scope: Optional[str],
        hosting_component: ResolvedHostingComponent,
    ) -> Dict[str, Any]:
        identity = hosting_component.oauth_identity
        credentials = base64.b64encode(
            f"{identity.client_id}:{identity.client_secret}".encode("utf-8")
        ).decode("utf-8")
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        if scope:
            request_data["scope"] = scope

        response = self._token_endpoint_session.post(
            f"{self._runtime_config.domain_url}/oauth2/v1/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {credentials}",
            },
            data=request_data,
            timeout=self._runtime_config.timeout_seconds,
        )
        return _oauth_result(_response_payload_or_raise(response, "OAuth exchange"))

    def _exchange_client_credentials_for_oauth(
        self,
        scope: Optional[str],
        hosting_component: ResolvedHostingComponent,
    ) -> Dict[str, Any]:
        identity = hosting_component.oauth_identity
        credentials = base64.b64encode(
            f"{identity.client_id}:{identity.client_secret}".encode("utf-8")
        ).decode("utf-8")
        request_data = {
            "grant_type": "client_credentials",
        }
        if scope:
            request_data["scope"] = scope

        response = self._token_endpoint_session.post(
            f"{self._runtime_config.domain_url}/oauth2/v1/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {credentials}",
            },
            data=request_data,
            timeout=self._runtime_config.timeout_seconds,
        )
        return _oauth_result(
            _response_payload_or_raise(response, "OAuth client credentials exchange")
        )

    def _exchange_oci_service_token(
        self,
        subject: str,
        hosting_component: ResolvedHostingComponent,
    ) -> Any:
        assertion = self._build_jwt_assertion(subject, hosting_component, "oci-service")
        return self._build_upst_signer(assertion, hosting_component)

    def _exchange_oracle_database_token(
        self,
        subject: str,
        hosting_component: ResolvedHostingComponent,
        scope: str,
    ) -> OracleDatabaseTokenResult:
        assertion = self._build_jwt_assertion(subject, hosting_component, "oracle-database")
        signer = self._build_upst_signer(assertion, hosting_component)
        public_key_pem, private_key_pem = self._signer_keypair_extractor(signer)
        db_token = self._db_token_generator(
            signer,
            public_key_pem,
            scope,
            self._runtime_config,
        )
        return _oracle_database_token_result(
            db_token,
            private_key_pem,
            principal_mode="user",
        )

    def _exchange_oracle_database_token_with_oci_principal(
        self,
        scope: str,
    ) -> OracleDatabaseTokenResult:
        signer = self._factory_oci_signer_builder(self._runtime_config)
        public_key_pem, private_key_pem = _generate_database_session_keypair_pem()
        db_token = self._db_token_generator(
            signer,
            public_key_pem,
            scope,
            self._runtime_config,
        )
        return _oracle_database_token_result(
            db_token,
            private_key_pem,
            principal_mode="oci_principal",
        )

    def _build_upst_signer(
        self,
        assertion: str,
        hosting_component: ResolvedHostingComponent,
    ) -> Any:
        identity = hosting_component.oauth_identity
        domain_id = _extract_identity_domain_id(self._runtime_config.domain_url)
        return self._token_exchange_signer_cls(
            assertion,
            domain_id,
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


def _resolve_legacy_config(
    config_or_overrides: Optional[Union[TokenFactoryConfig, Dict[str, Any]]],
    config: Optional[TokenFactoryConfig],
) -> Optional[TokenFactoryConfig]:
    if config is not None:
        return config
    if isinstance(config_or_overrides, TokenFactoryConfig):
        return config_or_overrides
    if config_or_overrides is None or isinstance(config_or_overrides, dict):
        return None
    raise TypeError(
        "TokenFactory expects no arguments, a config overrides dict, or a TokenFactoryConfig instance."
    )


def _resolver_from_oauth_apps(
    oauth_apps: Optional[Dict[str, Union[Dict[str, Any], OAuthClientInfo]]],
    runtime_config: TokenFactoryRuntimeConfig,
) -> Optional[OAuthClientResolver]:
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


def _coerce_oauth_client_info(
    client_key: str,
    value: Union[Dict[str, Any], OAuthClientInfo],
) -> OAuthClientInfo:
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
            info.private_key_secret_ocid,
            info.private_key_passphrase_secret_ocid,
            info.certificate_secret_ocid,
        ]
    )


def _require_client_key(client_key: Optional[str]) -> str:
    if not isinstance(client_key, str):
        raise OAuthClientResolutionError("client_key is required.")
    stripped = client_key.strip()
    if not stripped:
        raise OAuthClientResolutionError("client_key is required.")
    return stripped


def _normalize_get_token_arguments(
    credential: Credential,
    token_type: str,
) -> Tuple[Credential, str]:
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


def _require_oci_principal_database_auth_mode(
    runtime_config: TokenFactoryRuntimeConfig,
) -> None:
    oci_auth_mode = str(runtime_config.oci_auth_mode or "").strip().lower()
    if oci_auth_mode in {"", "instance-principal", "resource-principal"}:
        return
    raise ConfigurationError(
        "oracle-database credential selector 'OCI_PRINCIPAL' supports only "
        "TF_SHARED_OCI_AUTH_MODE=instance-principal or resource-principal."
    )


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


def _oracle_database_token_result(
    db_token: str,
    private_key_pem: str,
    *,
    principal_mode: str,
) -> OracleDatabaseTokenResult:
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


def _default_policy_provider(
    runtime_config: TokenFactoryRuntimeConfig,
    legacy_config: Optional[TokenFactoryConfig],
) -> AuthorizationPolicyProvider:
    if not runtime_config.authz_policy_secret_ocid:
        return StaticAuthorizationPolicyProvider(None)

    def read_secret(secret_ocid: str) -> str:
        config_for_secret_read = legacy_config or runtime_config
        return _fetch_secret_value_from_oci(
            secret_ocid,
            runtime_config.oci_region,
            config_for_secret_read,
        )

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


def _default_token_validator(runtime_config: TokenFactoryRuntimeConfig) -> Any:
    claim_overrides = [runtime_config.groups_claim or "groups"]
    trusted_issuers = _discover_jwt_trusted_issuers(
        runtime_config,
        claim_overrides,
    )
    return HybridTokenValidator(
        domain_url=runtime_config.domain_url,
        trusted_issuers=trusted_issuers,
        jwt_claim_overrides=claim_overrides,
        timeout_seconds=runtime_config.timeout_seconds,
    )


def _discover_jwt_trusted_issuers(
    runtime_config: TokenFactoryRuntimeConfig,
    required_claims: list[str],
) -> Dict[str, Dict[str, Any]]:
    discovery_url = f"{runtime_config.domain_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = requests.get(discovery_url, timeout=runtime_config.timeout_seconds)
        metadata = response.json()
    except Exception as exc:
        raise ConfigurationError(f"OIDC discovery failed: {exc}") from exc
    if not getattr(response, "ok", True):
        raise ConfigurationError(
            f"OIDC discovery failed [{getattr(response, 'status_code', 'unknown')}]: "
            f"{getattr(response, 'text', '')}"
        )
    if not isinstance(metadata, dict):
        raise ConfigurationError("OIDC discovery response must be a JSON object.")

    issuer = str(metadata.get("issuer") or "").strip()
    jwks_url = str(metadata.get("jwks_uri") or "").strip()
    if not issuer or not jwks_url:
        raise ConfigurationError("OIDC discovery response must include issuer and jwks_uri.")
    return {
        issuer: {
            "jwks_url": jwks_url,
            "algorithms": ["RS256"],
            "required_claims": required_claims,
        }
    }


def _response_payload_or_raise(response: Any, label: str) -> Dict[str, Any]:
    if not getattr(response, "ok", False):
        raise TokenExchangeError(
            f"{label} failed [{getattr(response, 'status_code', 'unknown')}]: "
            f"{getattr(response, 'text', '')}"
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


def _incoming_oauth_result(access_token: str) -> Dict[str, Any]:
    return {
        "token": access_token,
        "access_token": access_token,
        "expires_in": _expires_in(access_token),
        "token_type": "Bearer",
        "issued_token_type": "oauth",
        "source": "incoming_token",
    }


def _validated_token_can_be_passed_through(
    context: Dict[str, Any],
    issued_scope: str,
    requested_scope: str,
) -> bool:
    return _validated_token_has_scope(context, issued_scope) and _validated_token_has_audience(
        context,
        _resource_audience_for_request_scope(requested_scope),
    )


def _validated_token_has_scope(context: Dict[str, Any], scope: str) -> bool:
    validated = context.get("validated_assertion")
    incoming_scopes = getattr(validated, "incoming_scopes", None)
    if not incoming_scopes:
        return False
    return scope in set(incoming_scopes)


def _validated_token_has_audience(context: Dict[str, Any], audience: Optional[str]) -> bool:
    if audience is None:
        return True
    validated = context.get("validated_assertion")
    token_audience = getattr(validated, "audience", None)
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


def _normalize_groups(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split()
    elif isinstance(value, list):
        values = value
    else:
        values = [value]

    normalized = []
    seen = set()
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            normalized.append(text)
            seen.add(text)
    return normalized


def _jwt_audience(runtime_config: TokenFactoryRuntimeConfig, token_type: str) -> str:
    if token_type in {"oracle-database", "oci-service"}:
        return f"{runtime_config.domain_url}/oauth2/v1/token"
    return OCI_IDENTITY_AUDIENCE


def _propagation_trust_claim(
    hosting_component: ResolvedHostingComponent,
    token_type: str,
) -> Dict[str, str]:
    if token_type not in {"oracle-database", "oci-service"}:
        return {}
    if not hosting_component.propagation_trust_claim:
        return {}
    claim_name, separator, claim_value = hosting_component.propagation_trust_claim.partition(":")
    if separator != ":" or not claim_name.strip() or not claim_value.strip():
        raise ConfigurationError(
            "TF_CLIENT_PROPAGATION_TRUST_CLAIM must be formatted as claim_name:claim_value"
        )
    return {claim_name.strip(): claim_value.strip()}


def _load_private_key(private_key_pem: str, passphrase: Optional[str]):
    password = passphrase.encode("utf-8") if passphrase else None
    return serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=password,
        backend=default_backend(),
    )


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


__all__ = [
    "ConfigurationError",
    "ORACLE_DATABASE_CREDENTIAL_OCI_PRINCIPAL",
    "ORACLE_DATABASE_CREDENTIAL_PROCESS",
    "OracleDatabaseTokenResult",
    "TokenExchangeError",
    "TokenFactoryConfig",
    "TokenFactory",
]
