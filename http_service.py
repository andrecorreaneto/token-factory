import json
from typing import Any, Dict, Optional

from ._factory_support import (
    LOGGER,
    SUPPORTED_TARGET_TOOLS,
    TARGET_TOOLS_REQUIRING_SCOPE,
    ConfigurationError,
    TokenExchangeError,
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


def exchange_token(
    incoming_access_token: str,
    target_tool: str,
    scope: Optional[str],
    config: Optional[Dict[str, Any]] = None,
) -> Any:
    return TokenFactory(config).get_token(incoming_access_token, target_tool, scope)


def handle_request(
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    config: Optional[Dict[str, Any]] = None,
):
    target_tool = body.get("target_tool")
    LOGGER.info(
        "Handling token factory request target_tool=%s body_token_present=%s header_token_present=%s scope_present=%s.",
        target_tool,
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

    if not target_tool:
        LOGGER.warning("Rejecting request because target_tool is missing.")
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": "Provide target_tool in the JSON body."},
        )
    if target_tool not in SUPPORTED_TARGET_TOOLS:
        supported = ", ".join(SUPPORTED_TARGET_TOOLS)
        LOGGER.warning("Rejecting request because target_tool=%s is unsupported.", target_tool)
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": f"Unsupported target_tool '{target_tool}'. Supported values: {supported}"},
        )
    scope = _extract_request_scope(body)
    if target_tool in TARGET_TOOLS_REQUIRING_SCOPE and not scope:
        LOGGER.warning(
            "Rejecting request because scope is required for target_tool=%s.",
            target_tool,
        )
        return (
            400,
            {"Content-Type": "application/json"},
            {"message": f"Provide scope in the JSON body for target_tool '{target_tool}'."},
        )
    if target_tool == "oci-service":
        LOGGER.warning("Rejecting HTTP request for target_tool=oci-service because it is library-only.")
        return (
            400,
            {"Content-Type": "application/json"},
            {
                "message": "target_tool 'oci-service' is only supported through the direct "
                "library API because it returns a TokenExchangeSigner object."
            },
        )

    try:
        token_data = exchange_token(access_token, target_tool, scope, config)
        LOGGER.info("HTTP token request completed successfully target_tool=%s.", target_tool)
        return 200, {"Content-Type": "application/json"}, token_data
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
