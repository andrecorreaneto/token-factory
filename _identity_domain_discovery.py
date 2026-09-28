from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from ._factory_support import ConfigurationError


@dataclass(frozen=True)
class IdentityDomainMetadata:
    """Validated Identity Domain OIDC metadata used by one factory instance."""

    issuer: str
    jwks_uri: str
    token_endpoint: str
    introspection_endpoint: str


def discover_identity_domain_metadata(domain_url: str, timeout_seconds: int, session: Any = requests) -> IdentityDomainMetadata:
    """Load the required Identity Domain metadata from OIDC discovery."""
    normalized_domain_url = _validated_https_url(str(domain_url or "").strip().rstrip("/"), "identity_domain_url")
    discovery_url = f"{normalized_domain_url}/.well-known/openid-configuration"
    try:
        response = session.get(discovery_url, timeout=timeout_seconds, allow_redirects=False)
    except Exception:
        raise ConfigurationError(f"OIDC discovery request failed for '{discovery_url}'.") from None
    status_code = getattr(response, "status_code", None)
    if not isinstance(status_code, int) or status_code < 200 or status_code >= 300:
        raise ConfigurationError(f"OIDC discovery request failed for '{discovery_url}' with status {status_code if status_code is not None else 'unknown'}.")
    try:
        payload = response.json()
    except Exception:
        raise ConfigurationError(f"OIDC discovery response from '{discovery_url}' contains invalid JSON.") from None
    if not isinstance(payload, dict):
        raise ConfigurationError(f"OIDC discovery response from '{discovery_url}' must be a JSON object.")
    return IdentityDomainMetadata(
        issuer=_validated_metadata_url(payload, "issuer"),
        jwks_uri=_validated_metadata_url(payload, "jwks_uri"),
        token_endpoint=_validated_metadata_url(payload, "token_endpoint"),
        introspection_endpoint=_validated_metadata_url(payload, "introspection_endpoint"),
    )


def _validated_metadata_url(payload: dict, field_name: str) -> str:
    """Return one required and safe discovery URL."""
    value = str(payload.get(field_name) or "").strip()
    if not value:
        raise ConfigurationError(f"OIDC discovery response is missing required field '{field_name}'.")
    return _validated_https_url(value, field_name)


def _validated_https_url(value: str, label: str) -> str:
    """Require an absolute HTTPS URL without credentials, query, or fragment."""
    candidate = str(value or "").strip()
    if "?" in candidate or "#" in candidate:
        raise ConfigurationError(f"{label} must be an absolute HTTPS URL without credentials, query, or fragment.")
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise ConfigurationError(f"{label} must be an absolute HTTPS URL without credentials, query, or fragment.") from None
    if parsed.scheme.lower() != "https" or not hostname or username is not None or password is not None:
        raise ConfigurationError(f"{label} must be an absolute HTTPS URL without credentials, query, or fragment.")
    return candidate
