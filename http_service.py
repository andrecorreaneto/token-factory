"""Small HTTP adapter for TokenFactory request validation and response mapping."""

import json
from typing import Any, Dict, Optional

from ._factory_support import (
    LOGGER,
    SUPPORTED_TOKEN_TYPES,
    TOKEN_TYPES_REQUIRING_SCOPE,
    ConfigurationError,
    TokenExchangeError,
)
from ._errors import (
    AuthorizationError,
    AuthorizationPolicyError,
    CallerAssertionValidationError,
    OAuthClientResolutionError,
)
from .factory import TokenFactory


def _extract_bearer_token(headers: Optional[Dict[str, str]]) -> Optional[str]:
    if not headers:
        return None
    authorization = headers.get("authorization") or headers.get("Authorization")
    if not authorization:
        return None
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return authorization.strip()


def coerce_payload(payload: Any) -> Dict[str, Any]:
    """Coerce raw HTTP body input into the dictionary shape handled by TokenFactory."""
    if payload is None:
        return {}
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        stripped = payload.strip()
        if not stripped:
            return {}
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return {"access_token": stripped}
    return {}


def _extract_request_scope(body: Dict[str, Any]) -> Optional[str]:
    raw_scope = body.get("scope")
    if not isinstance(raw_scope, str):
        return None

    scope = raw_scope.strip()
    return scope or None


def _extract_client_key(body: Dict[str, Any]) -> Optional[str]:
    raw_client_key = body.get("client_key")
    if not isinstance(raw_client_key, str):
        return None

    stripped = raw_client_key.strip()
    if not stripped:
        return None
    return stripped


def exchange_token(incoming_access_token: str, token_type: str, scope: Optional[str], config: Optional[Dict[str, Any]] = None, client_key: Optional[str] = None) -> Any:
    """Create a TokenFactory and exchange the incoming access token."""
    return TokenFactory(config).get_token(
        incoming_access_token,
        token_type,
        scope,
        client_key=client_key,
    )


def handle_request(body: Dict[str, Any], headers: Optional[Dict[str, str]] = None, config: Optional[Dict[str, Any]] = None):
    """Handle an HTTP-style token request and return status, headers, and JSON body."""
    token_type = body.get("token_type")
    LOGGER.info(
        "Handling token factory request token_type=%s body_token_present=%s header_token_present=%s scope_present=%s.",
        token_type,
        any(body.get(key) for key in ("access_token", "token", "subject_token")),
        bool(_extract_bearer_token(headers)),
        isinstance(body.get("scope"), str) and bool(body.get("scope").strip()),
    )
    access_token = (
        body.get("access_token")
        or body.get("token")
        or body.get("subject_token")
        or _extract_bearer_token(headers)
    )
    if not access_token:
        LOGGER.warning("Rejecting request because no access token was provided.")
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": "Provide an access_token in the JSON body or Authorization header."},
        )

    if not token_type:
        LOGGER.warning("Rejecting request because token_type is missing.")
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": "Provide token_type in the JSON body."},
        )
    if token_type not in SUPPORTED_TOKEN_TYPES:
        supported = ", ".join(SUPPORTED_TOKEN_TYPES)
        LOGGER.warning("Rejecting request because token_type=%s is unsupported.", token_type)
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": f"Unsupported token_type '{token_type}'. Supported values: {supported}"},
        )
    if "caller_context" in body:
        LOGGER.warning("Rejecting request because caller_context is no longer supported.")
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": "caller_context is no longer supported; use client_key."},
        )
    client_key = _extract_client_key(body)
    if client_key is None:
        LOGGER.warning("Rejecting request because client_key is missing.")
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": "Provide client_key in the JSON body."},
        )
    scope = _extract_request_scope(body)
    if token_type in TOKEN_TYPES_REQUIRING_SCOPE and not scope:
        LOGGER.warning(
            "Rejecting request because scope is required for token_type=%s.",
            token_type,
        )
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": f"Provide scope in the JSON body for token_type '{token_type}'."},
        )
    if token_type == "oci-service":
        LOGGER.warning("Rejecting HTTP request for token_type=oci-service because it is library-only.")
        return (
            400,
            {"Content-Type": "application/json"},
            {
                "message": "token_type 'oci-service' is only supported through the direct "
                "library API because it returns a TokenExchangeSigner object."
            },
        )

    try:
        token_data = exchange_token(access_token, token_type, scope, config, client_key)
        LOGGER.info("HTTP token request completed successfully token_type=%s.", token_type)
        return 200, {"Content-Type": "application/json"}, token_data
    except CallerAssertionValidationError as exc:
        LOGGER.warning("Caller assertion validation failed.")
        return 401, {"Content-Type": "application/json"}, {"message": str(exc)}
    except AuthorizationError as exc:
        LOGGER.warning("Token request authorization failed.")
        return 403, {"Content-Type": "application/json"}, {"message": str(exc)}
    except AuthorizationPolicyError as exc:
        LOGGER.exception("Authorization policy error during token exchange.")
        return 500, {"Content-Type": "application/json"}, {"message": str(exc)}
    except OAuthClientResolutionError as exc:
        LOGGER.exception("OAuth client resolution failed.")
        return 500, {"Content-Type": "application/json"}, {"message": str(exc)}
    except ValueError as exc:
        return 400, {"Content-Type": "application/json"}, {"message": str(exc)}
    except ConfigurationError as exc:
        LOGGER.exception("Configuration error during token exchange.")
        return 500, {"Content-Type": "application/json"}, {"message": str(exc)}
    except TokenExchangeError as exc:
        LOGGER.exception("Token exchange failed.")
        return 502, {"Content-Type": "application/json"}, {"message": str(exc)}
    except Exception as exc:  # pragma: no cover - unexpected path
        LOGGER.exception("Unhandled error during token exchange.")
        return 500, {"Content-Type": "application/json"}, {"message": f"Unhandled error: {exc}"}
