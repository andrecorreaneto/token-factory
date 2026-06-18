import time
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode

import jwt
import requests
from oci.auth.signers import TokenExchangeSigner

from ._factory_support import (
    ConfigurationError,
    LOGGER,
    SUPPORTED_TARGET_TOOLS,
    TokenExchangeError,
    TokenFactoryConfig,
    _apply_log_level,
    _describe_credential_for_log,
    _describe_signer_credential_for_log,
    _exchange_assertion_for_oauth,
    _exchange_assertion_for_upst,
    _extract_identity_domain_id,
    _extract_token_exchange_signer_keypair_pem,
    _generate_db_token_with_dataplane,
    _get_token_exchange_credentials,
    _load_config,
    _log_method_entry,
    _redact_ocid,
    _truncate_for_log,
    build_oci_request_signer,
    build_signer_credential_from_profile,
    build_jwt_assertion,
)

Credential = Union[str, Dict[str, Any]]

class _ConfigLoader:
    @staticmethod
    def load(config_overrides: Optional[Dict[str, Any]] = None) -> TokenFactoryConfig:
        if config_overrides and "TOKEN_FACTORY_LOG_LEVEL" in config_overrides:
            _apply_log_level(config_overrides["TOKEN_FACTORY_LOG_LEVEL"])
        _log_method_entry("_ConfigLoader.load", override_count=len(config_overrides or {}))
        return _load_config(config_overrides)

class _SecretResolver:
    def __init__(self, config: TokenFactoryConfig):
        _log_method_entry("_SecretResolver.__init__", domain=config.domain_url, domain_region=config.domain_oci_region)
        self._config = config

    def get_token_exchange_credentials(self) -> Tuple[str, str]:
        _log_method_entry(
            "_SecretResolver.get_token_exchange_credentials",
            creds_source=(
                "vault-secret"
                if self._config.token_factory_creds_ocid
                else "direct-config"
            ),
            secret_ocid=_redact_ocid(self._config.token_factory_creds_ocid),
        )
        return _get_token_exchange_credentials(self._config)

class _AssertionService:
    def __init__(self, config: TokenFactoryConfig):
        _log_method_entry("_AssertionService.__init__", domain=config.domain_url)
        self._config = config

    def build_assertion(self, incoming_access_token: str, target_tool: str) -> str:
        _log_method_entry("_AssertionService.build_assertion", target_tool=target_tool, credential_kind="access_token")
        return build_jwt_assertion(incoming_access_token, self._config, target_tool)

class _UpstSignerFactory:
    def __init__(self, config: TokenFactoryConfig, assertion_service: _AssertionService, secret_resolver: _SecretResolver):
        _log_method_entry("_UpstSignerFactory.__init__", domain=config.domain_url, domain_region=config.domain_oci_region)
        self._config = config
        self._assertion_service = assertion_service
        self._secret_resolver = secret_resolver

    def exchange_signer(self, incoming_access_token: str, target_tool: str) -> TokenExchangeSigner:
        _log_method_entry("_UpstSignerFactory.exchange_signer", target_tool=target_tool, credential_kind="access_token", domain=self._config.domain_url)
        if not incoming_access_token:
            raise ValueError("Caller token is required")

        domain_id = _extract_identity_domain_id(self._config.domain_url)
        assertion = self._assertion_service.build_assertion(incoming_access_token, target_tool)
        client_id, client_secret = self._secret_resolver.get_token_exchange_credentials()
        flow_label = self._resolve_flow_label(target_tool)

        LOGGER.info(
            "Starting %s signer exchange target_tool=%s domain=%s domain_id=%s domain_region=%s.",
            flow_label,
            target_tool,
            self._config.domain_url,
            domain_id,
            self._config.domain_oci_region,
        )
        LOGGER.info(
            "Initializing %s TokenExchangeSigner target_tool=%s domain=%s domain_id=%s region=%s credential_secret=%s.",
            flow_label,
            target_tool,
            self._config.domain_url,
            domain_id,
            self._config.domain_oci_region,
            _redact_ocid(self._config.token_factory_creds_ocid),
        )

        try:
            signer = TokenExchangeSigner(assertion, domain_id, client_id, client_secret, region=self._config.domain_oci_region)
        except Exception as exc:
            response = getattr(exc, "response", None)
            if response is not None:
                LOGGER.error(
                    "%s signer initialization failed target_tool=%s domain=%s domain_id=%s region=%s status=%s response=%s error=%s.",
                    flow_label,
                    target_tool,
                    self._config.domain_url,
                    domain_id,
                    self._config.domain_oci_region,
                    getattr(response, "status_code", "unknown"),
                    _truncate_for_log(getattr(response, "text", "")),
                    _truncate_for_log(exc),
                )
                raise
            LOGGER.exception(
                "%s signer initialization failed target_tool=%s domain=%s domain_id=%s region=%s.",
                flow_label,
                target_tool,
                self._config.domain_url,
                domain_id,
                self._config.domain_oci_region,
            )
            raise

        LOGGER.info(
            "%s TokenExchangeSigner initialized successfully target_tool=%s domain=%s domain_id=%s region=%s.",
            flow_label,
            target_tool,
            self._config.domain_url,
            domain_id,
            self._config.domain_oci_region,
        )
        return signer

    def extract_keypair_pem(self, signer: TokenExchangeSigner) -> Tuple[str, str]:
        _log_method_entry("_UpstSignerFactory.extract_keypair_pem", signer_type=type(signer).__name__)
        return _extract_token_exchange_signer_keypair_pem(signer)

    # Preserved as a legacy manual UPST exchange reference while active OO flows
    # standardize on TokenExchangeSigner-based UPST acquisition.
    def exchange_assertion_for_upst_reference(self, assertion: str, public_key_pem: str, private_key_pem: Optional[str] = None) -> Dict[str, Any]:
        _log_method_entry("_UpstSignerFactory.exchange_assertion_for_upst_reference", public_key_present=bool(public_key_pem), private_key_attached=bool(private_key_pem))
        return _exchange_assertion_for_upst(assertion, public_key_pem, self._config, private_key_pem=private_key_pem)

    @staticmethod
    def _resolve_flow_label(target_tool: str) -> str:
        _log_method_entry("_UpstSignerFactory._resolve_flow_label", target_tool=target_tool)
        if target_tool == "oci-service":
            return "OCI service"
        if target_tool == "oracle-database":
            return "Oracle database UPST"
        return target_tool


class _OAuthExchangeClient:
    def __init__(self, config: TokenFactoryConfig, assertion_service: _AssertionService):
        _log_method_entry("_OAuthExchangeClient.__init__", domain=config.domain_url)
        self._config = config
        self._assertion_service = assertion_service

    def exchange_oauth_token(self, credential: Credential, scope: Optional[str], target_tool: str = "oauth") -> Dict[str, Any]:
        credential_trace = _describe_credential_for_log(credential)
        _log_method_entry("_OAuthExchangeClient.exchange_oauth_token", target_tool=target_tool, scope=scope, **credential_trace)
        if not credential:
            raise ValueError("Credential is required")

        LOGGER.info(
            "Starting %s exchange scope=%s credential_type=%s credential_kind=%s profile_name=%s.",
            target_tool,
            _truncate_for_log(scope, 120),
            credential_trace["credential_type"],
            credential_trace.get("credential_kind"),
            credential_trace.get("profile_name", "unset"),
        )
        signer_credential = self._resolve_signer_credential(credential)
        resolved_via = "oci_request_signer" if signer_credential is not None else "jwt_assertion"
        LOGGER.info(
            "%s exchange credential resolved target_tool=%s credential_kind=%s resolved_via=%s profile_name=%s.",
            target_tool,
            target_tool,
            credential_trace.get("credential_kind"),
            resolved_via,
            credential_trace.get("profile_name", "unset"),
        )
        if signer_credential is not None:
            signer_trace = _describe_signer_credential_for_log(signer_credential)
            LOGGER.info(
                "%s signer credential summary target_tool=%s region=%s key_source=%s pass_phrase_configured=%s.",
                target_tool,
                target_tool,
                signer_trace.get("region", "unset"),
                signer_trace.get("key_source", "unset"),
                signer_trace.get("pass_phrase_configured", False),
            )
            oauth_payload = self._exchange_oauth_token_with_signer_credential(signer_credential, scope, target_tool)
        else:
            assertion = self._assertion_service.build_assertion(credential, target_tool)
            oauth_payload = _exchange_assertion_for_oauth(assertion, scope, self._config)
        LOGGER.info(
            "%s exchange succeeded expires_in=%s token_type=%s.",
            target_tool,
            oauth_payload.get("expires_in"),
            oauth_payload.get("token_type", "Bearer"),
        )
        return {
            "token": oauth_payload["access_token"],
            "expires_in": oauth_payload.get("expires_in"),
            "token_type": oauth_payload.get("token_type", "Bearer"),
            "issued_token_type": "oauth",
        }

    def _exchange_oauth_token_with_signer_credential(self, credential: Dict[str, Any], scope: Optional[str], target_tool: str) -> Dict[str, Any]:
        _log_method_entry("_OAuthExchangeClient._exchange_oauth_token_with_signer_credential", target_tool=target_tool, scope=scope, resolved_via="oci_request_signer", **_describe_signer_credential_for_log(credential))
        signer = self._build_request_signer(credential)
        endpoint = f"{self._config.domain_url}/oauth2/v1/token"
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if scope:
            request_data["scope"] = scope

        LOGGER.info(
            "Submitting %s exchange request with OCI signer endpoint=%s timeout=%ss scope=%s signer_region=%s.",
            target_tool,
            endpoint,
            self._config.token_factory_timeout,
            _truncate_for_log(scope, 120),
            credential["region"],
        )
        response = requests.post(
            endpoint,
            data=urlencode(request_data),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            auth=signer,
            timeout=self._config.token_factory_timeout,
        )
        LOGGER.info(
            "Received %s exchange response endpoint=%s status=%s.",
            target_tool,
            endpoint,
            response.status_code,
        )

        if not response.ok:
            LOGGER.error(
                "%s exchange failed endpoint=%s status=%s response=%s.",
                target_tool,
                endpoint,
                response.status_code,
                _truncate_for_log(response.text),
            )
            raise TokenExchangeError(
                f"{target_tool} exchange failed [{response.status_code}]: {response.text}"
            )

        data = response.json()
        access_token = data.get("access_token") or data.get("token")
        if not access_token:
            raise TokenExchangeError(
                f"{target_tool} exchange response missing access_token"
            )
        data["access_token"] = access_token
        return data

    @staticmethod
    def _build_request_signer(credential: Dict[str, Any]):
        _log_method_entry("_OAuthExchangeClient._build_request_signer", **_describe_signer_credential_for_log(credential))
        signer_trace = _describe_signer_credential_for_log(credential)
        LOGGER.info(
            "Constructing OCI request signer region=%s key_source=%s pass_phrase_configured=%s.",
            signer_trace.get("region", "unset"),
            signer_trace.get("key_source", "unset"),
            signer_trace.get("pass_phrase_configured", False),
        )
        return build_oci_request_signer(credential)

    @classmethod
    def _resolve_signer_credential(cls, credential: Credential) -> Optional[Dict[str, Any]]:
        credential_trace = _describe_credential_for_log(credential)
        _log_method_entry("_OAuthExchangeClient._resolve_signer_credential", **credential_trace)
        if isinstance(credential, dict):
            LOGGER.info(
                "OAuth credential classified as signer dictionary credential_kind=%s.",
                credential_trace.get("credential_kind"),
            )
            return credential

        if isinstance(credential, str) and not cls._looks_like_access_token(credential):
            LOGGER.info(
                "OAuth credential classified as OCI CLI profile name credential_kind=%s profile_name=%s.",
                credential_trace.get("credential_kind"),
                credential_trace.get("profile_name", "unset"),
            )
            return cls._load_signer_credential_from_profile(credential)

        LOGGER.info(
            "OAuth credential classified as access token credential_kind=%s.",
            credential_trace.get("credential_kind"),
        )
        return None

    @staticmethod
    def _looks_like_access_token(credential: str) -> bool:
        looks_like_access_token = credential.count(".") == 2
        _log_method_entry("_OAuthExchangeClient._looks_like_access_token", credential_kind="access_token" if looks_like_access_token else "oci_cli_profile_name", segment_count=credential.count(".") + 1 if credential else 0)
        return looks_like_access_token

    @staticmethod
    def _load_signer_credential_from_profile(profile_name: str) -> Dict[str, Any]:
        _log_method_entry("_OAuthExchangeClient._load_signer_credential_from_profile", profile_name=profile_name)
        signer_credential = build_signer_credential_from_profile(profile_name)
        signer_trace = _describe_signer_credential_for_log(signer_credential)
        LOGGER.info(
            "Loaded OCI CLI profile for OAuth signer profile_name=%s region=%s key_source=%s pass_phrase_configured=%s.",
            profile_name,
            signer_trace.get("region", "unset"),
            signer_trace.get("key_source", "unset"),
            signer_trace.get("pass_phrase_configured", False),
        )
        return signer_credential


class _DatabaseTokenIssuer:
    def __init__(self, config: TokenFactoryConfig, upst_signer_factory: _UpstSignerFactory):
        _log_method_entry("_DatabaseTokenIssuer.__init__", domain=config.domain_url, domain_region=config.domain_oci_region)
        self._config = config
        self._upst_signer_factory = upst_signer_factory

    def exchange_oracle_database_token(self, incoming_access_token: str, scope: str) -> Tuple[str, str, int, str, str]:
        _log_method_entry("_DatabaseTokenIssuer.exchange_oracle_database_token", scope=scope, credential_kind="access_token", domain_region=getattr(self._config, "domain_oci_region", "unknown"))
        if not incoming_access_token:
            raise ValueError("Caller token is required")
        if not scope:
            raise ValueError("Scope is required for target_tool 'oracle-database'")

        LOGGER.info(
            "Starting oracle-database exchange scope=%s domain_region=%s.",
            _truncate_for_log(scope, 120),
            getattr(self._config, "domain_oci_region", "unknown"),
        )
        signer = self._upst_signer_factory.exchange_signer(incoming_access_token,"oracle-database")
        public_key_pem, private_key_pem = self._upst_signer_factory.extract_keypair_pem(signer)
        db_token = _generate_db_token_with_dataplane(signer, public_key_pem, scope, self._config)

        try:
            payload = jwt.decode(db_token, options={"verify_signature": False})
            expires_in = max(payload.get("exp", 0) - int(time.time()), 0)
        except Exception:
            expires_in = 3600

        LOGGER.info("Oracle database token issued successfully expires_in=%s scope=%s.", expires_in, _truncate_for_log(scope, 120))
        return db_token, private_key_pem, expires_in, "Bearer", "oracle-database"


class TokenFactory:
    def __init__(self, config_or_overrides: Optional[Union[TokenFactoryConfig, Dict[str, Any]]] = None, *, config: Optional[TokenFactoryConfig] = None):
        if config is not None and config_or_overrides is not None:
            raise ValueError("Pass either config_or_overrides or config, not both.")
        if config is not None:
            resolved_config = config
        elif isinstance(config_or_overrides, TokenFactoryConfig):
            resolved_config = config_or_overrides
        elif config_or_overrides is None or isinstance(config_or_overrides, dict):
            resolved_config = _ConfigLoader.load(config_or_overrides)
        else:
            raise TypeError(
                "TokenFactory expects no arguments, a config overrides dict, "
                "or a TokenFactoryConfig instance."
            )

        config = resolved_config
        _log_method_entry("TokenFactory.__init__", domain=config.domain_url, domain_region=config.domain_oci_region)
        self._config = config
        self._secret_resolver = _SecretResolver(config)
        self._assertion_service = _AssertionService(config)
        self._upst_signer_factory = _UpstSignerFactory(
            config,
            self._assertion_service,
            self._secret_resolver,
        )
        self._oauth_exchange_client = _OAuthExchangeClient(
            config,
            self._assertion_service,
        )
        self._database_token_issuer = _DatabaseTokenIssuer(
            config,
            self._upst_signer_factory,
        )

    @classmethod
    def from_env(cls, config_overrides: Optional[Dict[str, Any]] = None) -> "TokenFactory":
        _log_method_entry("TokenFactory.from_env", override_count=len(config_overrides or {}))
        return cls(config_overrides)

    def get_token(self, credential: Credential, target_tool: str, scope: Optional[str] = None) -> Any:
        """Exchange a credential for a target-tool-specific token.

        Args:
            credential:
                Either a caller access token string or an OCI signer credential
                dictionary. For ``oauth`` and ``userid``, a non-token string is
                also treated as an OCI CLI profile name loaded from
                ``~/.oci/config``. Signer dictionaries accept:
                ``tenancy``, ``user``, ``fingerprint``, ``region``, and exactly
                one of ``private_key_file``/``private_key_file_location`` or
                ``private_key_content``. Optional passphrase keys:
                ``pass_phrase`` or ``private_key_passphrase``.
            target_tool:
                One of ``oracle-database``, ``oci-service``, ``oauth``, or
                ``userid``.
            scope:
                Optional scope to request. Required for ``oracle-database`` and
                optional for ``oauth`` and ``userid``.
        """
        credential_trace = _describe_credential_for_log(credential)
        _log_method_entry("TokenFactory.get_token", target_tool=target_tool, scope=scope, **credential_trace)
        LOGGER.info(
            "Dispatching token exchange target_tool=%s scope_provided=%s credential_type=%s credential_kind=%s profile_name=%s.",
            target_tool,
            bool(scope),
            credential_trace["credential_type"],
            credential_trace.get("credential_kind"),
            credential_trace.get("profile_name", "unset"),
        )
        routes = {
            "oracle-database": lambda: self._exchange_oracle_database_token(
                self._require_access_token_credential(credential, "oracle-database"),
                scope,
            ),
            "oci-service": lambda: self._exchange_oci_service_token(
                self._require_access_token_credential(credential, "oci-service")
            ),
            "oauth": lambda: self._exchange_oauth_token(
                credential,
                scope,
                "oauth",
            ),
            "userid": lambda: self._exchange_userid(credential, scope),
        }
        if target_tool not in routes:
            supported = ", ".join(SUPPORTED_TARGET_TOOLS)
            raise ValueError(
                f"Unsupported target_tool '{target_tool}'. Supported values: {supported}"
            )
        if target_tool == "oracle-database" and not scope:
            raise ValueError(f"Scope is required for target_tool '{target_tool}'")

        result = routes[target_tool]()
        LOGGER.info(
            "Token exchange completed for target_tool=%s.",
            target_tool,
        )
        return result

    def _exchange_oracle_database_token(self, incoming_access_token: str, scope: str) -> Tuple[str, str, int, str, str]:
        _log_method_entry("TokenFactory._exchange_oracle_database_token", scope=scope, credential_kind="access_token")
        return self._database_token_issuer.exchange_oracle_database_token(incoming_access_token, scope)

    def _exchange_oci_service_token(self, incoming_access_token: str) -> TokenExchangeSigner:
        _log_method_entry("TokenFactory._exchange_oci_service_token", credential_kind="access_token")
        return self._upst_signer_factory.exchange_signer(incoming_access_token, "oci-service")

    def _exchange_oauth_token(self, credential: Credential, scope: Optional[str], target_tool: str = "oauth") -> Dict[str, Any]:
        _log_method_entry("TokenFactory._exchange_oauth_token", target_tool=target_tool, scope=scope, **_describe_credential_for_log(credential))
        return self._oauth_exchange_client.exchange_oauth_token(credential, scope, target_tool)

    def _exchange_userid(self, credential: Credential, scope: Optional[str]) -> Dict[str, Any]:
        _log_method_entry("TokenFactory._exchange_userid", scope=scope, **_describe_credential_for_log(credential))
        LOGGER.info(
            "Starting userid exchange scope=%s credential_kind=%s.",
            _truncate_for_log(scope, 120),
            _describe_credential_for_log(credential).get("credential_kind"),
        )
        oauth_payload = self._oauth_exchange_client.exchange_oauth_token(credential, scope, "userid")
        token = oauth_payload.get("token")
        if not token:
            raise TokenExchangeError(
                "OAuth token response missing token for userid target."
            )

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
        except Exception as exc:
            raise TokenExchangeError(
                f"Failed to decode OAuth token for userid target: {exc}"
            ) from exc

        subject = decoded.get("sub")
        if not subject:
            raise TokenExchangeError(
                "OAuth token response missing sub claim for userid target."
            )

        LOGGER.info("Userid exchange succeeded subject claim was present.")
        return {
            "issued_token_type": "userid",
            "user_id": subject,
        }

    @staticmethod
    def _require_access_token_credential(credential: Credential, target_tool: str) -> str:
        _log_method_entry("TokenFactory._require_access_token_credential", target_tool=target_tool, **_describe_credential_for_log(credential))
        if not isinstance(credential, str) or not credential:
            raise ValueError(
                f"target_tool '{target_tool}' requires credential to be a non-empty access token string."
            )
        return credential


__all__ = [
    "ConfigurationError",
    "TokenExchangeError",
    "TokenFactoryConfig",
    "TokenFactory",
]
