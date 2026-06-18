import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from oci.auth.signers import (
    InstancePrincipalsSecurityTokenSigner,
    TokenExchangeSigner,
    get_resource_principals_signer,
)
from oci.config import from_file as load_oci_config
from oci.identity_data_plane import DataplaneClient
from oci.identity_data_plane.models import GenerateScopedAccessTokenDetails
from oci.secrets import SecretsClient
from oci.signer import Signer


_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.FATAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "WARN": logging.WARN,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


def _resolve_log_level(value: Optional[str]) -> Tuple[str, int]:
    normalized = "INFO" if value is None else str(value).strip().upper()
    if normalized not in _LOG_LEVELS:
        valid_values = ", ".join(_LOG_LEVELS)
        raise ValueError(f"TOKEN_FACTORY_LOG_LEVEL must be one of: {valid_values}")
    return normalized, _LOG_LEVELS[normalized]


TOKEN_FACTORY_LOG_LEVEL, _LOG_LEVEL_NUMBER = _resolve_log_level(os.getenv("TOKEN_FACTORY_LOG_LEVEL"))
logging.basicConfig(level=_LOG_LEVEL_NUMBER)
LOGGER = logging.getLogger("token_factory")
LOGGER.setLevel(_LOG_LEVEL_NUMBER)


def _apply_log_level(value: Any) -> None:
    global TOKEN_FACTORY_LOG_LEVEL
    global _LOG_LEVEL_NUMBER

    TOKEN_FACTORY_LOG_LEVEL, _LOG_LEVEL_NUMBER = _resolve_log_level(value)
    LOGGER.setLevel(_LOG_LEVEL_NUMBER)


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


class TokenExchangeError(RuntimeError):
    """Raised when the upstream token exchange or DB token issuance fails."""


@dataclass(frozen=True)
class TokenFactoryConfig:
    domain_url: str
    domain_oci_region: str
    token_factory_creds_ocid: Optional[str]
    token_factory_creds: Optional[str]
    jwt_issuer: str
    assertion_key_path: Optional[str]
    assertion_key_pem: Optional[str]
    assertion_key_secret_ocid: Optional[str]
    assertion_key_passphrase: Optional[str]
    assertion_oci_region: Optional[str]
    assertion_cert_path: Optional[str]
    assertion_cert_pem: Optional[str]
    assertion_cert_secret_ocid: Optional[str]
    assertion_kid: Optional[str]
    token_factory_timeout: int
    propagation_trust_claim: Optional[str] = None
    log_full_assertion: bool = False
    oci_auth_mode: str = "instance-principal"
    oci_auth_profile: Optional[str] = "DEFAULT"
    assertion_key_passphrase_secret_ocid: Optional[str] = None


_ASSERTION_SIGNING_KEY = None
_ASSERTION_SIGNING_KEY_SOURCE = None
_ASSERTION_SIGNING_CERTIFICATE = None
_ASSERTION_SIGNING_CERTIFICATE_SOURCE = None
_TOKEN_EXCHANGE_CREDS_CACHE: Dict[
    Tuple[Optional[str], Optional[str], Optional[str], str, str], Tuple[str, str]
] = {}
SUPPORTED_TARGET_TOOLS = (
    "oracle-database",
    "oci-service",
    "oauth",
    "userid",
)
TARGET_TOOLS_REQUIRING_SCOPE = ("oracle-database",)
OCI_IDENTITY_AUDIENCE = "https://identity.oraclecloud.com/"
_ALLOWED_OCI_AUTH_MODES = {"instance-principal", "oci-profile", "resource-principal"}
_OCI_AUTH_MODE_ERROR = "TOKEN_FACTORY_OCI_AUTH_MODE must be one of: instance-principal, oci-profile, resource-principal"


def _config_value(name: str, config_overrides: Optional[Dict[str, Any]] = None, default: Optional[Any] = None, required: bool = False) -> Optional[Any]:
    _log_method_entry("_config_value", name=name, override_provided=bool(config_overrides and name in config_overrides), required=required)
    if config_overrides and name in config_overrides:
        value = config_overrides[name]
    else:
        value = os.getenv(name, default)

    if required and (value is None or value == ""):
        raise ConfigurationError(
            f"Missing required environment variable: {name}. "
            "Configure process environment (for example via a .env loader, container env, "
            "or OCI Function configuration) before calling TokenFactory.get_token."
        )

    return value


def _describe_value_source(*, pem: Optional[str], secret_ocid: Optional[str], path: Optional[str]) -> str:
    configured_sources = []
    if pem:
        configured_sources.append("pem")
    if secret_ocid:
        configured_sources.append("vault-secret")
    if path:
        configured_sources.append("path")
    return ",".join(configured_sources) if configured_sources else "unset"


def _redact_ocid(value: Optional[str]) -> str:
    if not value:
        return "unset"
    if len(value) <= 16:
        return value
    return f"{value[:16]}...{value[-8:]}"


def _truncate_for_log(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _normalize_log_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None or value == "":
        return "unset"
    return _truncate_for_log(value, 120)


def _format_log_fields(**fields: Any) -> str:
    return " ".join(
        f"{key}={_normalize_log_value(value)}"
        for key, value in fields.items()
        if value is not None
    )


def _log_method_entry(method_name: str, **fields: Any) -> None:
    details = _format_log_fields(**fields)
    if details:
        LOGGER.debug("Entering %s %s.", method_name, details)
        return
    LOGGER.debug("Entering %s.", method_name)


def _signer_key_source(credential: Dict[str, Any]) -> str:
    private_key_file = credential.get("private_key_file") or credential.get(
        "private_key_file_location"
    )
    if private_key_file:
        return "private_key_file"
    if credential.get("private_key_content"):
        return "private_key_content"
    return "missing"


def _describe_signer_credential_for_log(credential: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "credential_kind": "signer_dict",
        "region": credential.get("region"),
        "key_source": _signer_key_source(credential),
        "pass_phrase_configured": bool(
            credential.get("pass_phrase")
            or credential.get("private_key_passphrase")
        ),
        "tenancy_configured": bool(credential.get("tenancy")),
        "user_configured": bool(credential.get("user")),
        "fingerprint_configured": bool(credential.get("fingerprint")),
    }


def _describe_credential_for_log(credential: Any) -> Dict[str, Any]:
    summary = {"credential_type": type(credential).__name__}
    if isinstance(credential, dict):
        summary.update(_describe_signer_credential_for_log(credential))
        return summary
    if isinstance(credential, str):
        if not credential:
            summary["credential_kind"] = "empty"
            return summary
        if credential.count(".") == 2:
            summary["credential_kind"] = "access_token"
            return summary
        summary["credential_kind"] = "oci_cli_profile_name"
        summary["profile_name"] = credential
        return summary
    summary["credential_kind"] = "unsupported"
    return summary


def build_signer_credential_from_profile(profile_name: str) -> Dict[str, Any]:
    try:
        profile = load_oci_config(profile_name=profile_name)
    except Exception as exc:
        raise ConfigurationError(
            f"Unable to load OCI CLI profile '{profile_name}': {exc}"
        ) from exc

    signer_credential = {
        "tenancy": profile.get("tenancy"),
        "user": profile.get("user"),
        "fingerprint": profile.get("fingerprint"),
        "region": profile.get("region"),
        "pass_phrase": profile.get("pass_phrase"),
    }
    private_key_file = profile.get("key_file")
    if private_key_file:
        signer_credential["private_key_file"] = private_key_file
    else:
        private_key_content = profile.get("key_content")
        if private_key_content:
            signer_credential["private_key_content"] = private_key_content
    return signer_credential


def build_oci_request_signer(credential: Dict[str, Any]) -> Signer:
    tenancy = credential.get("tenancy")
    user = credential.get("user")
    fingerprint = credential.get("fingerprint")
    region = credential.get("region")
    private_key_file = credential.get("private_key_file") or credential.get(
        "private_key_file_location"
    )
    private_key_content = credential.get("private_key_content")
    pass_phrase = credential.get("pass_phrase")
    if pass_phrase is None:
        pass_phrase = credential.get("private_key_passphrase")

    missing_fields = [
        name
        for name, value in (
            ("tenancy", tenancy),
            ("user", user),
            ("fingerprint", fingerprint),
            ("region", region),
        )
        if not value
    ]
    if missing_fields:
        missing = ", ".join(missing_fields)
        raise ValueError(f"Signer credential is missing required field(s): {missing}")

    if bool(private_key_file) == bool(private_key_content):
        raise ValueError(
            "Signer credential must provide exactly one of private_key_file "
            "(or private_key_file_location) and private_key_content."
        )

    return Signer(
        tenancy=tenancy,
        user=user,
        fingerprint=fingerprint,
        private_key_file_location=private_key_file,
        private_key_content=private_key_content,
        pass_phrase=pass_phrase,
    )


def _extract_identity_domain_id(domain_url: str) -> str:
    _log_method_entry("_extract_identity_domain_id", domain_url=domain_url)
    candidate = domain_url.strip()
    if not candidate:
        raise ConfigurationError("TOKEN_FACTORY_DOMAIN_URL must not be empty.")

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = parsed.hostname
    if not hostname:
        raise ConfigurationError(
            f"Unable to parse identity domain host from TOKEN_FACTORY_DOMAIN_URL '{domain_url}'."
        )

    suffix = ".identity.oraclecloud.com"
    if hostname.endswith(suffix):
        domain_id = hostname[: -len(suffix)]
        if domain_id:
            return domain_id

    if "." not in hostname:
        return hostname

    raise ConfigurationError(
        "Unable to derive identity domain ID from TOKEN_FACTORY_DOMAIN_URL. "
        "Expected a host like '<domain_id>.identity.oraclecloud.com'."
    )


def _coerce_bool(value: Any, setting_name: str) -> bool:
    _log_method_entry("_coerce_bool", setting_name=setting_name)
    if isinstance(value, bool):
        return value
    if value is None:
        return False

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off", ""}:
        return False

    raise ConfigurationError(
        f"{setting_name} must be a boolean-compatible value, got '{value}'"
    )


def _normalize_oci_auth_mode(value: Any) -> str:
    _log_method_entry("_normalize_oci_auth_mode", value=value)
    if value is None:
        raise ConfigurationError(_OCI_AUTH_MODE_ERROR)
    normalized = str(value).strip().lower()
    if not normalized or normalized not in _ALLOWED_OCI_AUTH_MODES:
        raise ConfigurationError(_OCI_AUTH_MODE_ERROR)
    return normalized


def _load_config(config_overrides: Optional[Dict[str, Any]] = None) -> TokenFactoryConfig:
    _log_method_entry("_load_config", override_count=len(config_overrides or {}))
    domain_url = str(_config_value("TOKEN_FACTORY_DOMAIN_URL", config_overrides, required=True)).rstrip("/")
    domain_oci_region = str(_config_value("TOKEN_FACTORY_DOMAIN_REGION", config_overrides, required=True))
    token_factory_creds_ocid = _config_value("TOKEN_FACTORY_CREDS_SECRET_OCID", config_overrides)
    token_factory_creds = _config_value("TOKEN_FACTORY_CREDS", config_overrides)
    if not token_factory_creds_ocid and not token_factory_creds:
        raise ConfigurationError(
            "Provide one of: TOKEN_FACTORY_CREDS_SECRET_OCID or TOKEN_FACTORY_CREDS"
        )
    jwt_issuer = str(_config_value("TOKEN_FACTORY_ISSUER", config_overrides, required=True))
    propagation_trust_claim = _config_value(
        "TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM",
        config_overrides,
    )
    log_full_assertion = _coerce_bool(
        _config_value("TOKEN_FACTORY_LOG_FULL_ASSERTION", config_overrides, False),
        "TOKEN_FACTORY_LOG_FULL_ASSERTION",
    )
    oci_auth_mode = _normalize_oci_auth_mode(
        _config_value("TOKEN_FACTORY_OCI_AUTH_MODE", config_overrides, "instance-principal")
    )
    oci_auth_profile_raw = _config_value("TOKEN_FACTORY_OCI_AUTH_PROFILE", config_overrides, "DEFAULT")
    oci_auth_profile_candidate = (
        str(oci_auth_profile_raw).strip() if oci_auth_profile_raw is not None else ""
    )
    oci_auth_profile = oci_auth_profile_candidate or "DEFAULT"
    timeout_raw = _config_value("TOKEN_FACTORY_TIMEOUT_SECONDS", config_overrides, "30")
    try:
        timeout = int(timeout_raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"TOKEN_FACTORY_TIMEOUT_SECONDS must be an integer, got '{timeout_raw}'"
        ) from exc

    assertion_key_path = _config_value("TOKEN_FACTORY_PRIVATE_KEY_PATH", config_overrides)
    assertion_key_pem = _config_value("TOKEN_FACTORY_PRIVATE_KEY_PEM", config_overrides)
    assertion_key_secret_ocid = _config_value(
        "TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID", config_overrides
    )
    assertion_cert_path = _config_value("TOKEN_FACTORY_CERT_PATH", config_overrides)
    assertion_cert_pem = _config_value("TOKEN_FACTORY_CERT_PEM", config_overrides)
    assertion_cert_secret_ocid = _config_value(
        "TOKEN_FACTORY_CERT_SECRET_OCID", config_overrides
    )
    assertion_kid = _config_value("TOKEN_FACTORY_KID", config_overrides)
    assertion_key_passphrase = _config_value(
        "TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE", config_overrides
    )
    assertion_key_passphrase_secret_ocid = _config_value(
        "TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID", config_overrides
    )
    assertion_oci_region = _config_value("TOKEN_FACTORY_OCI_REGION", config_overrides)

    if not any([assertion_key_path, assertion_key_pem, assertion_key_secret_ocid]):
        raise ConfigurationError(
            "Provide at least one of: TOKEN_FACTORY_PRIVATE_KEY_PEM, "
            "TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID, or TOKEN_FACTORY_PRIVATE_KEY_PATH"
        )

    if not any([assertion_cert_path, assertion_cert_pem, assertion_cert_secret_ocid]):
        raise ConfigurationError(
            "Provide at least one of: TOKEN_FACTORY_CERT_PEM, "
            "TOKEN_FACTORY_CERT_SECRET_OCID, or TOKEN_FACTORY_CERT_PATH"
        )

    LOGGER.info(
        "Loaded token factory configuration for domain=%s domain_region=%s timeout=%ss "
        "key_sources=%s cert_sources=%s kid_configured=%s",
        domain_url,
        domain_oci_region,
        timeout,
        _describe_value_source(
            pem=assertion_key_pem,
            secret_ocid=assertion_key_secret_ocid,
            path=assertion_key_path,
        ),
        _describe_value_source(
            pem=assertion_cert_pem,
            secret_ocid=assertion_cert_secret_ocid,
            path=assertion_cert_path,
        ),
        bool(assertion_kid),
    )
    LOGGER.info(
        "Optional JWT propagation trust claim configured=%s source=%s.",
        bool(propagation_trust_claim),
        "override-dict"
        if config_overrides and "TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM" in config_overrides
        else "environment",
    )
    LOGGER.info("Full JWT assertion logging enabled=%s.", log_full_assertion)

    return TokenFactoryConfig(
        domain_url=domain_url,
        domain_oci_region=domain_oci_region,
        token_factory_creds_ocid=str(token_factory_creds_ocid)
        if token_factory_creds_ocid
        else None,
        token_factory_creds=str(token_factory_creds) if token_factory_creds else None,
        jwt_issuer=jwt_issuer,
        propagation_trust_claim=str(propagation_trust_claim) if propagation_trust_claim else None,
        assertion_key_path=assertion_key_path,
        assertion_key_pem=assertion_key_pem,
        assertion_key_secret_ocid=assertion_key_secret_ocid,
        assertion_key_passphrase=str(assertion_key_passphrase) if assertion_key_passphrase else None,
        assertion_oci_region=str(assertion_oci_region) if assertion_oci_region else None,
        assertion_cert_path=assertion_cert_path,
        assertion_cert_pem=assertion_cert_pem,
        assertion_cert_secret_ocid=assertion_cert_secret_ocid,
        assertion_kid=str(assertion_kid) if assertion_kid else None,
        token_factory_timeout=timeout,
        log_full_assertion=log_full_assertion,
        oci_auth_mode=oci_auth_mode,
        oci_auth_profile=oci_auth_profile,
        assertion_key_passphrase_secret_ocid=(
            str(assertion_key_passphrase_secret_ocid)
            if assertion_key_passphrase_secret_ocid
            else None
        ),
    )


def _resolve_secret_region(secret_ocid: str, explicit_region: Optional[str]) -> str:
    _log_method_entry("_resolve_secret_region", explicit_region=explicit_region, secret_ocid=_redact_ocid(secret_ocid))
    if explicit_region:
        return explicit_region
    parts = secret_ocid.split(".")
    if len(parts) > 3 and parts[3]:
        return parts[3]
    raise ConfigurationError(
        f"Unable to determine OCI region for secret {secret_ocid}. "
        "Set TOKEN_FACTORY_OCI_REGION explicitly."
    )


def _get_factory_oci_signer(config: TokenFactoryConfig):
    _log_method_entry("_get_factory_oci_signer", oci_auth_mode=config.oci_auth_mode, oci_auth_profile=config.oci_auth_profile)
    if config.oci_auth_mode == "resource-principal":
        try:
            LOGGER.info("Attempting factory OCI signer initialization with resource principals.")
            return get_resource_principals_signer()
        except Exception as resource_principal_exc:
            raise ConfigurationError(
                "Failed to initialize factory OCI signer with resource principal: "
                f"{resource_principal_exc}."
            ) from resource_principal_exc

    try:
        LOGGER.info("Attempting factory OCI signer initialization with instance principals.")
        return InstancePrincipalsSecurityTokenSigner()
    except Exception as instance_principal_exc:
        if config.oci_auth_mode != "oci-profile":
            raise ConfigurationError(
                "Failed to initialize factory OCI signer with instance principal: "
                f"{instance_principal_exc}; profile fallback is disabled because mode is "
                f"'{config.oci_auth_mode}'."
            ) from instance_principal_exc

        profile_name = config.oci_auth_profile or "DEFAULT"
        try:
            LOGGER.info(
                "Instance principal signer initialization failed; attempting OCI profile fallback profile=%s.",
                profile_name,
            )
            signer_credential = build_signer_credential_from_profile(profile_name)
            return build_oci_request_signer(signer_credential)
        except Exception as profile_exc:
            both_failures = ExceptionGroup(
                "Factory OCI signer initialization failed for instance principal and OCI profile fallback.",
                [instance_principal_exc, profile_exc],
            )
            raise ConfigurationError(
                "Failed to initialize factory OCI signer. "
                f"Both instance principal and OCI profile fallback failed for profile '{profile_name}'."
            ) from both_failures


def _fetch_secret_value_from_oci(
    secret_ocid: str, region: Optional[str], config: TokenFactoryConfig
) -> str:
    _log_method_entry(
        "_fetch_secret_value_from_oci",
        secret_ocid=_redact_ocid(secret_ocid),
        region=region,
        oci_auth_mode=config.oci_auth_mode,
    )
    resolved_region = _resolve_secret_region(secret_ocid, region)
    LOGGER.info(
        "Fetching OCI Vault secret value secret_ocid=%s region=%s.",
        _redact_ocid(secret_ocid),
        resolved_region,
    )
    client = SecretsClient(
        config={"region": resolved_region},
        signer=_get_factory_oci_signer(config),
    )
    bundle = client.get_secret_bundle(secret_ocid).data
    content = getattr(bundle, "secret_bundle_content", None)
    if not content or not getattr(content, "content", None):
        raise ConfigurationError(f"Secret bundle {secret_ocid} is missing content.")

    try:
        decoded = base64.b64decode(content.content).decode("utf-8")
    except Exception as exc:
        raise ConfigurationError(
            f"Failed to decode secret bundle content for {secret_ocid}: {exc}"
        ) from exc

    LOGGER.info(
        "Fetched OCI Vault secret value successfully secret_ocid=%s region=%s.",
        _redact_ocid(secret_ocid),
        resolved_region,
    )
    return decoded


def _parse_token_factory_credentials(
    raw_value: str,
    source_name: str,
) -> Tuple[str, str]:
    _log_method_entry(
        "_parse_token_factory_credentials",
        raw_value_present=bool(raw_value),
        contains_separator=":" in raw_value,
        source_name=source_name,
    )
    if ":" not in raw_value:
        raise ConfigurationError(
            f"{source_name} must be formatted as client_id:client_secret"
        )

    client_id, client_secret = raw_value.split(":", 1)
    if not client_id or not client_secret:
        raise ConfigurationError(
            f"{source_name} must contain both client_id and client_secret"
        )
    return client_id, client_secret


def _get_token_exchange_credentials(config: TokenFactoryConfig) -> Tuple[str, str]:
    _log_method_entry(
        "_get_token_exchange_credentials",
        secret_ocid=_redact_ocid(config.token_factory_creds_ocid),
        direct_creds_configured=bool(config.token_factory_creds),
        region=config.assertion_oci_region or "derived-from-ocid",
    )
    cache_key = (
        config.token_factory_creds_ocid,
        config.token_factory_creds,
        config.assertion_oci_region,
        config.oci_auth_mode,
        config.oci_auth_profile or "DEFAULT",
    )
    if cache_key in _TOKEN_EXCHANGE_CREDS_CACHE:
        LOGGER.info(
            "Using cached token factory credentials source=%s secret_ocid=%s region=%s.",
            "vault-secret" if config.token_factory_creds_ocid else "direct-config",
            _redact_ocid(config.token_factory_creds_ocid),
            config.assertion_oci_region or "derived-from-ocid",
        )
        return _TOKEN_EXCHANGE_CREDS_CACHE[cache_key]

    if config.token_factory_creds_ocid:
        LOGGER.info(
            "Resolving token factory credentials from OCI Vault secret_ocid=%s region=%s.",
            _redact_ocid(config.token_factory_creds_ocid),
            config.assertion_oci_region or "derived-from-ocid",
        )
        raw_value = _fetch_secret_value_from_oci(
            config.token_factory_creds_ocid,
            config.assertion_oci_region,
            config,
        )
        credentials = _parse_token_factory_credentials(
            raw_value,
            "TOKEN_FACTORY_CREDS_SECRET_OCID secret",
        )
    else:
        LOGGER.info("Resolving token factory credentials from TOKEN_FACTORY_CREDS.")
        credentials = _parse_token_factory_credentials(
            config.token_factory_creds or "",
            "TOKEN_FACTORY_CREDS",
        )
    _TOKEN_EXCHANGE_CREDS_CACHE[cache_key] = credentials
    LOGGER.info(
        "Token factory credentials resolved successfully source=%s secret_ocid=%s.",
        "vault-secret" if config.token_factory_creds_ocid else "direct-config",
        _redact_ocid(config.token_factory_creds_ocid),
    )
    return credentials


def _load_assertion_signing_key(config: TokenFactoryConfig):
    _log_method_entry(
        "_load_assertion_signing_key",
        key_source=_describe_value_source(
            pem=config.assertion_key_pem,
            secret_ocid=config.assertion_key_secret_ocid,
            path=config.assertion_key_path,
        ),
        region=config.assertion_oci_region,
        passphrase_configured=bool(
            config.assertion_key_passphrase
            or config.assertion_key_passphrase_secret_ocid
        ),
    )
    global _ASSERTION_SIGNING_KEY
    global _ASSERTION_SIGNING_KEY_SOURCE

    source_key = (
        config.assertion_key_secret_ocid,
        config.assertion_key_path,
        config.assertion_key_pem,
        config.assertion_key_passphrase,
        config.assertion_key_passphrase_secret_ocid,
        config.assertion_oci_region,
        config.oci_auth_mode,
        config.oci_auth_profile or "DEFAULT",
    )
    if _ASSERTION_SIGNING_KEY is not None and source_key == _ASSERTION_SIGNING_KEY_SOURCE:
        LOGGER.info("Using cached JWT assertion signing key.")
        return _ASSERTION_SIGNING_KEY

    LOGGER.info(
        "JWT assertion signing key retrieval order: "
        "TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID -> TOKEN_FACTORY_PRIVATE_KEY_PATH -> TOKEN_FACTORY_PRIVATE_KEY_PEM."
    )
    if config.assertion_key_secret_ocid:
        LOGGER.info(
            "Loading JWT assertion signing key from TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID."
        )
        key_bytes = _fetch_secret_value_from_oci(
            config.assertion_key_secret_ocid,
            config.assertion_oci_region,
            config,
        ).encode("utf-8")
    elif config.assertion_key_path:
        key_path = Path(config.assertion_key_path)
        if not key_path.exists():
            raise ConfigurationError(f"JWT assertion key file not found: {key_path}")
        LOGGER.info("Loading JWT assertion signing key from TOKEN_FACTORY_PRIVATE_KEY_PATH.")
        key_bytes = key_path.read_bytes()
    elif config.assertion_key_pem:
        LOGGER.info("Loading JWT assertion signing key from TOKEN_FACTORY_PRIVATE_KEY_PEM.")
        key_bytes = config.assertion_key_pem.encode("utf-8")
    else:
        raise ConfigurationError("JWT assertion key path is not configured.")

    if config.assertion_key_passphrase_secret_ocid:
        LOGGER.info(
            "Loading JWT assertion signing key passphrase from TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID."
        )
        passphrase = _fetch_secret_value_from_oci(
            config.assertion_key_passphrase_secret_ocid,
            config.assertion_oci_region,
            config,
        )
    else:
        passphrase = config.assertion_key_passphrase

    password = passphrase.encode("utf-8") if passphrase else None
    _ASSERTION_SIGNING_KEY = serialization.load_pem_private_key(
        key_bytes,
        password=password,
        backend=default_backend(),
    )
    _ASSERTION_SIGNING_KEY_SOURCE = source_key
    LOGGER.info("JWT assertion signing key loaded successfully.")
    return _ASSERTION_SIGNING_KEY


def _load_assertion_signing_certificate(config: TokenFactoryConfig) -> Optional[x509.Certificate]:
    _log_method_entry("_load_assertion_signing_certificate", cert_source=_describe_value_source(pem=config.assertion_cert_pem, secret_ocid=config.assertion_cert_secret_ocid, path=config.assertion_cert_path), region=config.assertion_oci_region)
    global _ASSERTION_SIGNING_CERTIFICATE
    global _ASSERTION_SIGNING_CERTIFICATE_SOURCE

    source_key = (
        config.assertion_cert_secret_ocid,
        config.assertion_cert_path,
        config.assertion_cert_pem,
        config.assertion_oci_region,
        config.oci_auth_mode,
        config.oci_auth_profile or "DEFAULT",
    )
    LOGGER.info(
        "JWT assertion certificate retrieval order: "
        "TOKEN_FACTORY_CERT_SECRET_OCID -> TOKEN_FACTORY_CERT_PATH -> TOKEN_FACTORY_CERT_PEM."
    )
    if not any(source_key[:3]):
        LOGGER.info(
            "No JWT assertion certificate source is configured; x5t will be omitted unless "
            "TOKEN_FACTORY_KID is provided."
        )
        return None
    if (
        _ASSERTION_SIGNING_CERTIFICATE is not None
        and source_key == _ASSERTION_SIGNING_CERTIFICATE_SOURCE
    ):
        LOGGER.info("Using cached JWT assertion certificate.")
        return _ASSERTION_SIGNING_CERTIFICATE

    if config.assertion_cert_secret_ocid:
        LOGGER.info(
            "Attempting JWT assertion certificate load from TOKEN_FACTORY_CERT_SECRET_OCID."
        )
        cert_bytes = _fetch_secret_value_from_oci(
            config.assertion_cert_secret_ocid,
            config.assertion_oci_region,
            config,
        ).encode("utf-8")
    elif config.assertion_cert_path:
        LOGGER.info("Attempting JWT assertion certificate load from TOKEN_FACTORY_CERT_PATH.")
        cert_path = Path(config.assertion_cert_path)
        if not cert_path.exists():
            raise ConfigurationError(f"JWT assertion certificate file not found: {cert_path}")
        cert_bytes = cert_path.read_bytes()
    elif config.assertion_cert_pem:
        LOGGER.info("Attempting JWT assertion certificate load from TOKEN_FACTORY_CERT_PEM.")
        cert_bytes = config.assertion_cert_pem.encode("utf-8")
    else:
        raise ConfigurationError("JWT assertion certificate path is not configured.")

    try:
        certificate = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(cert_bytes)
        except ValueError as exc:
            raise ConfigurationError(
                "JWT assertion certificate must be valid PEM or DER encoded X.509 data."
            ) from exc

    _ASSERTION_SIGNING_CERTIFICATE = certificate
    _ASSERTION_SIGNING_CERTIFICATE_SOURCE = source_key
    LOGGER.info("JWT assertion certificate loaded successfully.")
    return certificate


def _extract_token_exchange_signer_keypair_pem(signer: TokenExchangeSigner) -> Tuple[str, str]:
    _log_method_entry("_extract_token_exchange_signer_keypair_pem", signer_type=type(signer).__name__)
    session_key_supplier = getattr(signer, "session_key_supplier", None)
    if session_key_supplier is None or not hasattr(session_key_supplier, "get_key_pair"):
        raise TokenExchangeError("UPST signer did not expose a session key supplier.")

    key_pair = session_key_supplier.get_key_pair()
    private_key = key_pair.get("private")
    public_key = key_pair.get("public")
    if private_key is None or public_key is None:
        raise TokenExchangeError("UPST signer session keypair is incomplete.")

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return public_key_pem, private_key_pem


def _to_single_line_public_key(public_key_pem: str) -> str:
    _log_method_entry("_to_single_line_public_key", public_key_present=bool(public_key_pem))
    segments = []
    for line in public_key_pem.splitlines():
        line = line.strip()
        if line and "BEGIN" not in line and "END" not in line:
            segments.append(line)
    return "".join(segments)


def _exchange_assertion_for_upst(assertion: str, public_key_pem: str, config: TokenFactoryConfig, private_key_pem: Optional[str] = None) -> dict:
    _log_method_entry("_exchange_assertion_for_upst", assertion_present=bool(assertion), public_key_present=bool(public_key_pem), private_key_attached=bool(private_key_pem), domain_region=config.domain_oci_region)
    client_id, client_secret = _get_token_exchange_credentials(config)
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    endpoint = f"{config.domain_url}/oauth2/v1/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {credentials}",
    }
    public_key_value = _to_single_line_public_key(public_key_pem)
    request_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:oci:token-type:oci-upst",
        "subject_token": assertion,
        "subject_token_type": "jwt",
        "public_key": public_key_value,
    }
    logged_headers = {
        "Content-Type": headers["Content-Type"],
        "Authorization": "<redacted>",
    }
    logged_request_data = dict(request_data)
    logged_request_data["subject_token"] = (
        assertion if config.log_full_assertion else "<redacted>"
    )
    LOGGER.info(
        "Submitting UPST token exchange request endpoint=%s timeout=%ss credential_secret=%s "
        "domain_region=%s private_key_attached=%s.",
        endpoint,
        config.token_factory_timeout,
        _redact_ocid(config.token_factory_creds_ocid),
        config.domain_oci_region,
        private_key_pem is not None,
    )
    try:
        assertion_header = jwt.get_unverified_header(assertion)
        assertion_payload = jwt.decode(
            assertion,
            options={"verify_signature": False, "verify_aud": False},
        )
        LOGGER.info(
            "UPST subject_token decoded header=%s.",
            json.dumps(assertion_header, sort_keys=True),
        )
        LOGGER.info(
            "UPST subject_token decoded payload=%s.",
            json.dumps(assertion_payload, sort_keys=True),
        )
    except Exception as exc:
        LOGGER.warning("Unable to decode UPST subject_token for logging: %s.", exc)
    LOGGER.info(
        "UPST token exchange request headers=%s.",
        json.dumps(logged_headers, sort_keys=True),
    )
    LOGGER.info(
        "UPST token exchange request data=%s.",
        json.dumps(logged_request_data, sort_keys=True),
    )
    response = requests.post(
        endpoint,
        headers=headers,
        data=request_data,
        timeout=config.token_factory_timeout,
    )
    LOGGER.info(
        "Received UPST token exchange response endpoint=%s status=%s.",
        endpoint,
        response.status_code,
    )

    if not response.ok:
        LOGGER.error(
            "UPST token exchange failed endpoint=%s status=%s response=%s.",
            endpoint,
            response.status_code,
            _truncate_for_log(response.text),
        )
        raise TokenExchangeError(
            f"UPST exchange failed [{response.status_code}]: {response.text}"
        )

    data = response.json()
    access_token = data.get("access_token") or data.get("token")
    if not access_token:
        raise TokenExchangeError("UPST exchange response missing access_token")
    data["access_token"] = access_token
    if private_key_pem is not None:
        data["private_key_pem"] = private_key_pem
    LOGGER.info(
        "UPST token exchange succeeded endpoint=%s expires_in=%s token_type=%s.",
        endpoint,
        data.get("expires_in"),
        data.get("token_type", "Bearer"),
    )
    return data


def _exchange_assertion_for_oauth(assertion: str, scope: Optional[str], config: TokenFactoryConfig) -> dict:
    _log_method_entry("_exchange_assertion_for_oauth", assertion_present=bool(assertion), scope=scope, domain=config.domain_url)
    client_id, client_secret = _get_token_exchange_credentials(config)
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode(
        "utf-8"
    )
    endpoint = f"{config.domain_url}/oauth2/v1/token"
    LOGGER.info(
        "Submitting OAuth token exchange request endpoint=%s timeout=%ss credential_secret=%s "
        "scope=%s.",
        endpoint,
        config.token_factory_timeout,
        _redact_ocid(config.token_factory_creds_ocid),
        _truncate_for_log(scope, 120),
    )
    request_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
    }
    if scope:
        request_data["scope"] = scope
    response = requests.post(
        endpoint,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        },
        data=request_data,
        timeout=config.token_factory_timeout,
    )
    LOGGER.info(
        "Received OAuth token exchange response endpoint=%s status=%s.",
        endpoint,
        response.status_code,
    )

    if not response.ok:
        LOGGER.error(
            "OAuth token exchange failed endpoint=%s status=%s response=%s.",
            endpoint,
            response.status_code,
            _truncate_for_log(response.text),
        )
        raise TokenExchangeError(
            f"OAuth exchange failed [{response.status_code}]: {response.text}"
        )

    data = response.json()
    access_token = data.get("access_token") or data.get("token")
    if not access_token:
        raise TokenExchangeError("OAuth exchange response missing access_token")
    data["access_token"] = access_token
    LOGGER.info(
        "OAuth token exchange succeeded endpoint=%s expires_in=%s token_type=%s.",
        endpoint,
        data.get("expires_in"),
        data.get("token_type", "Bearer"),
    )
    return data


def _generate_db_token_with_dataplane(signer: Any, public_key_pem: str, scope: str, config: TokenFactoryConfig) -> str:
    _log_method_entry("_generate_db_token_with_dataplane", signer_type=type(signer).__name__, public_key_present=bool(public_key_pem), scope=scope, domain_region=config.domain_oci_region)
    LOGGER.info(
        "Requesting Oracle Database scoped access token domain_region=%s scope=%s.",
        config.domain_oci_region,
        _truncate_for_log(scope, 120),
    )
    client = DataplaneClient(config={"region": config.domain_oci_region}, signer=signer)
    details = GenerateScopedAccessTokenDetails(
        scope=scope,
        public_key=public_key_pem,
    )
    response = client.generate_scoped_access_token(
        generate_scoped_access_token_details=details
    )
    return response.data.token


def _resolve_jwt_assertion_audience(config: TokenFactoryConfig, target_tool: str) -> str:
    _log_method_entry("_resolve_jwt_assertion_audience", target_tool=target_tool, domain=config.domain_url)
    if target_tool in ("oracle-database", "oci-service"):
        return f"{config.domain_url}/oauth2/v1/token"
    if target_tool in ("oauth", "userid"):
        return OCI_IDENTITY_AUDIENCE

    supported = ", ".join(SUPPORTED_TARGET_TOOLS)
    raise ValueError(
        f"Unsupported target_tool '{target_tool}' for JWT assertion. Supported values: {supported}"
    )


def _resolve_jwt_assertion_x5t(config: TokenFactoryConfig) -> Optional[str]:
    _log_method_entry("_resolve_jwt_assertion_x5t", domain=config.domain_url)
    certificate = _load_assertion_signing_certificate(config)
    if certificate is None:
        return None

    certificate_public_key = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signing_key_public_key = _load_assertion_signing_key(config).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public_key != signing_key_public_key:
        raise ConfigurationError(
            "JWT assertion certificate does not match the configured private key."
        )

    thumbprint = certificate.fingerprint(hashes.SHA1())
    return base64.urlsafe_b64encode(thumbprint).rstrip(b"=").decode("utf-8")


def _resolve_jwt_assertion_header_claims(config: TokenFactoryConfig, target_tool: str) -> Dict[str, str]:
    _log_method_entry("_resolve_jwt_assertion_header_claims", target_tool=target_tool, kid_configured=bool(config.assertion_kid))
    if target_tool in ("oauth", "userid"):
        if config.assertion_kid:
            return {"kid": config.assertion_kid}

        # x5t = _resolve_jwt_assertion_x5t(config)
        # if x5t:
        #     return {"x5t": x5t}

        LOGGER.info(
            "No x5t or kid is configured for %s; Falling back to identity domain SIGNING_KEY alias.",
            target_tool,
        )
        return {}

    return {}


def _parse_propagation_trust_claim(raw_value: str) -> Tuple[str, str]:
    _log_method_entry("_parse_propagation_trust_claim", raw_value_present=bool(raw_value))
    claim_name, separator, claim_value = raw_value.partition(":")
    claim_name = claim_name.strip()
    claim_value = claim_value.strip()
    if separator != ":" or not claim_name or not claim_value:
        raise ConfigurationError(
            "TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM must be formatted as claim_name:claim_value"
        )
    return claim_name, claim_value


def _resolve_propagation_trust_claim(config: TokenFactoryConfig, target_tool: str) -> Dict[str, str]:
    _log_method_entry("_resolve_propagation_trust_claim", target_tool=target_tool, configured=bool(config.propagation_trust_claim))
    if target_tool not in ("oracle-database", "oci-service"):
        return {}
    if not config.propagation_trust_claim:
        return {}

    claim_name, claim_value = _parse_propagation_trust_claim(config.propagation_trust_claim)
    return {claim_name: claim_value}


def build_jwt_assertion(incoming_access_token: str, config: TokenFactoryConfig, target_tool: str) -> str:
    _log_method_entry("build_jwt_assertion", target_tool=target_tool, domain=config.domain_url, credential_kind="access_token")
    now = int(time.time())
    header_claims = _resolve_jwt_assertion_header_claims(config, target_tool)
    audience = _resolve_jwt_assertion_audience(config, target_tool)
    propagation_trust_claim = _resolve_propagation_trust_claim(config, target_tool)
    payload = {
        "iss": config.jwt_issuer,
        "sub": _extract_subject(incoming_access_token),
        "aud": audience,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    payload.update(propagation_trust_claim)
    header = {"alg": "RS256", "typ": "JWT"}
    header.update(header_claims)
    LOGGER.info(
        "Building JWT assertion target_tool=%s audience=%s header_claims=%s propagation_claims=%s.",
        target_tool,
        audience,
        ",".join(sorted(header_claims.keys())) if header_claims else "none",
        ",".join(sorted(propagation_trust_claim.keys())) if propagation_trust_claim else "none",
    )
    LOGGER.info("JWT assertion header=%s.", json.dumps(header, sort_keys=True))
    LOGGER.info("JWT assertion payload=%s.", json.dumps(payload, sort_keys=True))

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(
        b"="
    ).decode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(
        b"="
    ).decode("utf-8")
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    signature = _load_assertion_signing_key(config).sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("utf-8")
    assertion = f"{header_b64}.{payload_b64}.{signature_b64}"
    if config.log_full_assertion:
        LOGGER.warning(
            "Full JWT assertion logging is enabled; this may expose replay-sensitive material."
        )
        LOGGER.info("JWT assertion compact=%s.", assertion)
    return assertion


def _extract_subject(access_token: str) -> str:
    _log_method_entry("_extract_subject", credential_kind="access_token")
    decoded = jwt.decode(access_token, options={"verify_signature": False})
    return decoded.get("sub") or decoded.get("preferred_username", "unknown")


__all__ = [
    "ConfigurationError",
    "LOGGER",
    "OCI_IDENTITY_AUDIENCE",
    "SUPPORTED_TARGET_TOOLS",
    "TARGET_TOOLS_REQUIRING_SCOPE",
    "TokenExchangeError",
    "TokenFactoryConfig",
    "_exchange_assertion_for_oauth",
    "_exchange_assertion_for_upst",
    "_extract_identity_domain_id",
    "_extract_token_exchange_signer_keypair_pem",
    "_generate_db_token_with_dataplane",
    "_get_token_exchange_credentials",
    "_describe_credential_for_log",
    "_describe_signer_credential_for_log",
    "_load_config",
    "_log_method_entry",
    "_redact_ocid",
    "_truncate_for_log",
    "build_oci_request_signer",
    "build_signer_credential_from_profile",
    "build_jwt_assertion",
]
