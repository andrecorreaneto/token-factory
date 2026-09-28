import base64
import hashlib
import logging
import os
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from oci.auth.signers import (
    InstancePrincipalsSecurityTokenSigner,
    TokenExchangeSigner,
    get_oke_workload_identity_resource_principal_signer,
    get_resource_principals_signer,
)
from oci.config import from_file as load_oci_config
from oci.identity_data_plane import DataplaneClient
from oci.identity_data_plane.models import GenerateScopedAccessTokenDetails
from oci.secrets import SecretsClient
from oci.signer import Signer

from ._runtime_config import TokenFactoryRuntimeConfig


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
        raise ValueError(f"TF_SHARED_LOG_LEVEL must be one of: {valid_values}")
    return normalized, _LOG_LEVELS[normalized]


TF_SHARED_LOG_LEVEL, _LOG_LEVEL_NUMBER = _resolve_log_level(os.getenv("TF_SHARED_LOG_LEVEL"))
logging.basicConfig(level=_LOG_LEVEL_NUMBER)
LOGGER = logging.getLogger("token_factory")
LOGGER.setLevel(_LOG_LEVEL_NUMBER)


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


class TokenExchangeError(RuntimeError):
    """Raised when upstream token exchange or database token issuance fails."""


class KmsJwtSigner:
    """Signs compact-JWS inputs through an OCI KMS asymmetric key."""

    def __init__(self, key_id: str, key_version_id: str, crypto_endpoint: str, factory_signer_builder: Any, runtime_config: Any):
        self._key_id = key_id
        self._key_version_id = key_version_id
        self._crypto_endpoint = crypto_endpoint
        self._factory_signer_builder = factory_signer_builder
        self._runtime_config = runtime_config

    def sign(self, signing_input: bytes) -> bytes:
        from oci.key_management import KmsCryptoClient
        from oci.key_management.models import SignDataDetails

        client = KmsCryptoClient(config={"region": self._runtime_config.oci_region}, service_endpoint=self._crypto_endpoint, signer=self._factory_signer_builder(self._runtime_config))
        digest = hashlib.sha256(signing_input).digest()
        details = SignDataDetails(message=base64.b64encode(digest).decode("ascii"), message_type="DIGEST", key_id=self._key_id, key_version_id=self._key_version_id, signing_algorithm="SHA_256_RSA_PKCS1_V1_5")
        response = client.sign(details)
        try:
            return base64.b64decode(response.data.signature)
        except Exception as exc:
            raise TokenExchangeError(f"OCI KMS returned an invalid JWT signature: {exc}") from exc


SUPPORTED_TOKEN_TYPES = (
    "oracle-database",
    "oci-service",
    "oauth",
    "userid",
)
TOKEN_TYPES_REQUIRING_SCOPE = ("oracle-database", "oauth")
OCI_IDENTITY_AUDIENCE = "https://identity.oraclecloud.com/"
_ALLOWED_OCI_AUTH_MODES = {"instance-principal", "oci-profile", "resource-principal", "oke-workload-identity"}
_OCI_AUTH_MODE_ERROR = "TF_SHARED_OCI_AUTH_MODE must be one of: instance-principal, oci-profile, resource-principal, oke-workload-identity"


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


def build_signer_credential_from_profile(profile_name: str) -> Dict[str, Any]:
    try:
        profile = load_oci_config(profile_name=profile_name)
    except Exception as exc:
        raise ConfigurationError(f"Unable to load OCI CLI profile '{profile_name}': {exc}") from exc

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
    elif profile.get("key_content"):
        signer_credential["private_key_content"] = profile.get("key_content")
    return signer_credential


def build_oci_request_signer(credential: Dict[str, Any]) -> Signer:
    tenancy = credential.get("tenancy")
    user = credential.get("user")
    fingerprint = credential.get("fingerprint")
    private_key_file = credential.get("private_key_file") or credential.get("private_key_file_location")
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
            ("region", credential.get("region")),
        )
        if not value
    ]
    if missing_fields:
        raise ValueError(f"Signer credential is missing required field(s): {', '.join(missing_fields)}")
    if bool(private_key_file) == bool(private_key_content):
        raise ValueError("Signer credential must provide exactly one of private_key_file (or private_key_file_location) and private_key_content.")

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
        raise ConfigurationError("TF_SHARED_DOMAIN_URL must not be empty.")

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = parsed.hostname
    if not hostname:
        raise ConfigurationError(f"Unable to parse identity domain host from TF_SHARED_DOMAIN_URL '{domain_url}'.")

    suffix = ".identity.oraclecloud.com"
    if hostname.endswith(suffix):
        domain_id = hostname[: -len(suffix)]
        if domain_id:
            return domain_id
    if "." not in hostname:
        return hostname
    raise ConfigurationError("Unable to derive identity domain ID from TF_SHARED_DOMAIN_URL. Expected a host like '<domain_id>.identity.oraclecloud.com'.")


def _normalize_oci_auth_mode(value: Any) -> str:
    if value is None:
        raise ConfigurationError(_OCI_AUTH_MODE_ERROR)
    normalized = str(value).strip().lower()
    if not normalized or normalized not in _ALLOWED_OCI_AUTH_MODES:
        raise ConfigurationError(_OCI_AUTH_MODE_ERROR)
    return normalized


def _resolve_secret_region(secret_ocid: str, explicit_region: Optional[str]) -> str:
    _log_method_entry("_resolve_secret_region", explicit_region=explicit_region, secret_ocid=_redact_ocid(secret_ocid))
    if explicit_region:
        return explicit_region
    parts = secret_ocid.split(".")
    if len(parts) > 3 and parts[3]:
        return parts[3]
    raise ConfigurationError(f"Unable to determine OCI region for secret {secret_ocid}. Set TF_SHARED_OCI_REGION explicitly.")


def _get_factory_oci_signer(config: Any):
    oci_auth_mode = _normalize_oci_auth_mode(getattr(config, "oci_auth_mode", "instance-principal"))
    oci_auth_profile = getattr(config, "oci_auth_profile", "DEFAULT") or "DEFAULT"
    _log_method_entry("_get_factory_oci_signer", oci_auth_mode=oci_auth_mode, oci_auth_profile=oci_auth_profile)
    if oci_auth_mode == "resource-principal":
        try:
            LOGGER.info("Attempting factory OCI signer initialization with resource principals.")
            return get_resource_principals_signer()
        except Exception as exc:
            raise ConfigurationError(f"Failed to initialize factory OCI signer with resource principal: {exc}.") from exc
    if oci_auth_mode == "oke-workload-identity":
        try:
            LOGGER.info("Attempting factory OCI signer initialization with OKE workload identity.")
            return get_oke_workload_identity_resource_principal_signer()
        except Exception as exc:
            raise ConfigurationError(f"Failed to initialize factory OCI signer with OKE workload identity: {exc}.") from exc

    try:
        LOGGER.info("Attempting factory OCI signer initialization with instance principals.")
        return InstancePrincipalsSecurityTokenSigner()
    except Exception as instance_principal_exc:
        if oci_auth_mode != "oci-profile":
            raise ConfigurationError(
                "Failed to initialize factory OCI signer with instance principal: "
                f"{instance_principal_exc}; profile fallback is disabled because mode is '{oci_auth_mode}'."
            ) from instance_principal_exc

        try:
            LOGGER.info("Instance principal signer initialization failed; attempting OCI profile fallback profile=%s.", oci_auth_profile)
            signer_credential = build_signer_credential_from_profile(oci_auth_profile)
            return build_oci_request_signer(signer_credential)
        except Exception as profile_exc:
            both_failures = ExceptionGroup(
                "Factory OCI signer initialization failed for instance principal and OCI profile fallback.",
                [instance_principal_exc, profile_exc],
            )
            raise ConfigurationError(f"Failed to initialize factory OCI signer. Both instance principal and OCI profile fallback failed for profile '{oci_auth_profile}'.") from both_failures


def _fetch_secret_value_from_oci(secret_ocid: str, region: Optional[str], config: Any) -> str:
    _log_method_entry("_fetch_secret_value_from_oci", secret_ocid=_redact_ocid(secret_ocid), region=region, oci_auth_mode=getattr(config, "oci_auth_mode", None))
    resolved_region = _resolve_secret_region(secret_ocid, region)
    LOGGER.info("Fetching OCI Vault secret value secret_ocid=%s region=%s.", _redact_ocid(secret_ocid), resolved_region)
    client = SecretsClient(config={"region": resolved_region}, signer=_get_factory_oci_signer(config))
    bundle = client.get_secret_bundle(secret_ocid).data
    content = getattr(bundle, "secret_bundle_content", None)
    if not content or not getattr(content, "content", None):
        raise ConfigurationError(f"Secret bundle {secret_ocid} is missing content.")

    try:
        decoded = base64.b64decode(content.content).decode("utf-8")
    except Exception as exc:
        raise ConfigurationError(f"Failed to decode secret bundle content for {secret_ocid}: {exc}") from exc
    LOGGER.info("Fetched OCI Vault secret value successfully secret_ocid=%s region=%s.", _redact_ocid(secret_ocid), resolved_region)
    return decoded


def _parse_token_factory_credentials(raw_value: str, source_name: str) -> Tuple[str, str]:
    _log_method_entry("_parse_token_factory_credentials", raw_value_present=bool(raw_value), contains_separator=":" in raw_value, source_name=source_name)
    if ":" not in raw_value:
        raise ConfigurationError(f"{source_name} must be formatted as client_id:client_secret")
    client_id, client_secret = raw_value.split(":", 1)
    if not client_id or not client_secret:
        raise ConfigurationError(f"{source_name} must contain both client_id and client_secret")
    return client_id, client_secret


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


def _generate_db_token_with_dataplane(signer: Any, public_key_pem: str, scope: str, config: TokenFactoryRuntimeConfig) -> str:
    domain_region = getattr(config, "domain_region", None)
    if not domain_region:
        raise ConfigurationError("TokenFactory domain region is required for database token generation.")
    _log_method_entry("_generate_db_token_with_dataplane", signer_type=type(signer).__name__, public_key_present=bool(public_key_pem), scope=scope, domain_region=domain_region)
    LOGGER.info("Requesting Oracle Database scoped access token domain_region=%s scope=%s.", domain_region, _truncate_for_log(scope, 120))
    client = DataplaneClient(config={"region": domain_region}, signer=signer)
    details = GenerateScopedAccessTokenDetails(scope=scope, public_key=public_key_pem)
    response = client.generate_scoped_access_token(generate_scoped_access_token_details=details)
    return response.data.token
