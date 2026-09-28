from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt
import requests

from ._errors import CallerAssertionValidationError
from ._normalization import normalize_audience, normalize_scopes, normalize_unique_strings
from ._oauth_client_resolution import ResolvedHostingComponent


@dataclass(frozen=True)
class ValidatedCallerAssertion:
    issuer: Optional[str]
    audience: List[str]
    incoming_scopes: List[str]
    claims: Dict[str, Any]


class TokenValidator:
    def __init__(self, introspection_endpoint: str, timeout_seconds: int = 30, session: Any = requests):
        self._introspection_endpoint = introspection_endpoint
        self._timeout_seconds = timeout_seconds
        self._session = session

    def validate(self, token: str, hosting_component: ResolvedHostingComponent) -> ValidatedCallerAssertion:
        try:
            response = self._session.post(
                self._introspection_endpoint,
                data={"token": token},
                auth=(
                    hosting_component.oauth_identity.client_id,
                    hosting_component.oauth_identity.client_secret,
                ),
                timeout=self._timeout_seconds,
            )
            payload = response.json()
        except Exception as exc:
            raise CallerAssertionValidationError(
                f"Token introspection failed: {exc}"
            ) from exc

        if not getattr(response, "ok", True):
            raise CallerAssertionValidationError(
                f"Token introspection failed [{getattr(response, 'status_code', 'unknown')}]: "
                f"{getattr(response, 'text', '')}"
            )
        if payload.get("active") is not True:
            raise CallerAssertionValidationError("Incoming caller assertion is inactive.")

        return _validated_from_claims(payload, hosting_component)


class JwtTokenValidator:
    def __init__(self, trusted_issuers: Dict[str, Dict[str, Any]]):
        self._trusted_issuers = dict(trusted_issuers)

    def validate(self, token: str, hosting_component: ResolvedHostingComponent) -> ValidatedCallerAssertion:
        try:
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_aud": False},
            )
        except Exception as exc:
            raise CallerAssertionValidationError(f"JWT cannot be decoded: {exc}") from exc

        issuer = unverified.get("iss")
        settings = self._trusted_issuers.get(issuer)
        if not settings:
            raise CallerAssertionValidationError(f"Untrusted JWT issuer '{issuer}'.")

        key = _resolve_jwt_key(settings, token)
        algorithms = settings.get("algorithms", ["RS256"])
        leeway = int(settings.get("leeway_seconds", 0))
        audience = hosting_component.resource_audiences or None
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=algorithms,
                issuer=issuer,
                audience=audience,
                leeway=leeway,
            )
        except Exception as exc:
            raise CallerAssertionValidationError(f"JWT validation failed: {exc}") from exc

        for claim_name in settings.get("required_claims", []):
            if claim_name not in claims:
                raise CallerAssertionValidationError(f"JWT is missing required claim '{claim_name}'.")
        for claim_name, expected_value in settings.get("required_claim_values", {}).items():
            if claims.get(claim_name) != expected_value:
                raise CallerAssertionValidationError(f"JWT claim '{claim_name}' has an unexpected value.")

        return _validated_from_claims(claims, hosting_component)


class HybridTokenValidator:
    def __init__(self, introspection_endpoint: str, trusted_issuers: Dict[str, Dict[str, Any]], jwt_claim_overrides: List[str], timeout_seconds: int = 30, session: Any = requests):
        normalized_overrides = _normalize_claim_names(jwt_claim_overrides)
        if not normalized_overrides:
            raise ValueError("jwt_claim_overrides must contain at least one claim name.")
        self._introspection_validator = TokenValidator(
            introspection_endpoint=introspection_endpoint,
            timeout_seconds=timeout_seconds,
            session=session,
        )
        self._jwt_validator = JwtTokenValidator(trusted_issuers)
        self._jwt_claim_overrides = normalized_overrides

    def validate(self, token: str, hosting_component: ResolvedHostingComponent) -> ValidatedCallerAssertion:
        introspected = self._introspection_validator.validate(token, hosting_component)
        signed = self._jwt_validator.validate(token, hosting_component)

        claims = dict(introspected.claims)
        for claim_name in self._jwt_claim_overrides:
            if claim_name in signed.claims:
                claims[claim_name] = signed.claims[claim_name]

        return ValidatedCallerAssertion(
            issuer=introspected.issuer,
            audience=introspected.audience,
            incoming_scopes=introspected.incoming_scopes,
            claims=claims,
        )


def _validated_from_claims(claims: Dict[str, Any], hosting_component: ResolvedHostingComponent) -> ValidatedCallerAssertion:
    audience = normalize_audience(claims.get("aud"))
    if hosting_component.resource_audiences:
        if not set(audience).intersection(hosting_component.resource_audiences):
            raise CallerAssertionValidationError(
                "Incoming caller assertion audience does not match the selected hosting component."
            )

    incoming_scopes = normalize_scopes(claims.get("scope") or claims.get("scp"))
    required_incoming_scopes = set(hosting_component.required_incoming_scopes)
    if required_incoming_scopes and not required_incoming_scopes.intersection(incoming_scopes):
        raise CallerAssertionValidationError(
            "Incoming caller assertion is missing an accepted required scope. "
            "Accepted scope(s): " + ", ".join(sorted(required_incoming_scopes))
        )

    return ValidatedCallerAssertion(
        issuer=claims.get("iss"),
        audience=audience,
        incoming_scopes=incoming_scopes,
        claims=dict(claims),
    )


def _normalize_claim_names(values: List[str]) -> List[str]:
    return normalize_unique_strings(values or [])


def _resolve_jwt_key(settings: Dict[str, Any], token: str) -> Any:
    configured_sources = [
        source
        for source in ("jwks_url", "public_key_pem", "certificate_pem")
        if settings.get(source)
    ]
    if len(configured_sources) != 1:
        raise CallerAssertionValidationError(
            "JWT validator issuer settings require exactly one trust material source."
        )
    if settings.get("jwks_url"):
        return jwt.PyJWKClient(settings["jwks_url"]).get_signing_key_from_jwt(token).key
    return settings.get("public_key_pem") or settings.get("certificate_pem")
