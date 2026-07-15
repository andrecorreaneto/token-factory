import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ._errors import AuthorizationError, AuthorizationPolicyError
from ._normalization import normalize_unique_strings


@dataclass(frozen=True)
class AuthorizationPolicy:
    version: int
    grants: Dict[str, Dict[str, List[str]]]


@dataclass(frozen=True)
class AuthorizationRequest:
    subject: str
    groups: List[str]
    token_type: str
    scope: str


class AuthorizationPolicyProvider:
    def load_policy(self) -> Optional[AuthorizationPolicy]:
        raise NotImplementedError


class StaticAuthorizationPolicyProvider(AuthorizationPolicyProvider):
    def __init__(self, policy: Optional[AuthorizationPolicy]):
        self._policy = policy

    @classmethod
    def from_dict(cls, value: Optional[dict]) -> "StaticAuthorizationPolicyProvider":
        if value is None:
            return cls(None)
        return cls(_parse_policy(value))

    def load_policy(self) -> Optional[AuthorizationPolicy]:
        return self._policy


class VaultJsonAuthorizationPolicyProvider(AuthorizationPolicyProvider):
    def __init__(self, secret_ocid: str, secret_reader: Callable[[str], str]):
        self._secret_ocid = secret_ocid
        self._secret_reader = secret_reader

    def load_policy(self) -> Optional[AuthorizationPolicy]:
        try:
            raw_value = self._secret_reader(self._secret_ocid)
        except Exception as exc:
            raise AuthorizationPolicyError(
                f"Failed to load authorization policy secret '{self._secret_ocid}': {exc}"
            ) from exc

        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise AuthorizationPolicyError("Authorization policy secret is not valid JSON.") from exc
        return _parse_policy(payload)


class SignedVaultAuthorizationPolicyProvider(AuthorizationPolicyProvider):
    def __init__(self, secret_ocid: str, secret_reader: Callable[[str], str], trusted_signers: List[Dict[str, str]], expected_domain_url: str, expected_environment: Optional[str] = None, expected_tenant_id: Optional[str] = None, now_provider: Optional[Callable[[], Any]] = None):
        self._secret_ocid = secret_ocid
        self._secret_reader = secret_reader
        self._trusted_signers = trusted_signers
        self._expected_domain_url = expected_domain_url.rstrip("/")
        self._expected_environment = expected_environment
        self._expected_tenant_id = expected_tenant_id
        self._now_provider = now_provider

    def load_policy(self) -> Optional[AuthorizationPolicy]:
        try:
            raw_value = self._secret_reader(self._secret_ocid)
        except Exception as exc:
            raise AuthorizationPolicyError(
                f"Failed to load authorization policy secret '{self._secret_ocid}': {exc}"
            ) from exc

        try:
            envelope = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise AuthorizationPolicyError("Authorization policy secret is not valid JSON.") from exc

        _verify_signed_policy_envelope(
            envelope,
            trusted_signers=self._trusted_signers,
            expected_domain_url=self._expected_domain_url,
            expected_environment=self._expected_environment,
            expected_tenant_id=self._expected_tenant_id,
            now=(self._now_provider() if self._now_provider else datetime.now(timezone.utc)),
        )
        return _parse_policy(envelope.get("policy"))


class GroupScopeAuthorizer:
    def __init__(self, policy_or_provider: Optional[AuthorizationPolicy | AuthorizationPolicyProvider]):
        self._policy_or_provider = policy_or_provider

    def authorize(self, request: AuthorizationRequest) -> None:
        requested_scopes = normalize_unique_strings(request.scope.split())
        if not requested_scopes:
            raise AuthorizationError("Requested scope must not be empty.")

        policy = self._load_policy()
        if policy is None:
            raise AuthorizationError("No authorization policy is configured.")

        token_type_grants = policy.grants.get(request.token_type, {})
        user_groups = normalize_unique_strings(request.groups)
        effective_scopes = set()
        for group in user_groups:
            effective_scopes.update(token_type_grants.get(group, []))

        missing_scopes = sorted(set(requested_scopes) - effective_scopes)
        if missing_scopes:
            raise AuthorizationError(
                "Subject "
                f"'{request.subject}' is not authorized for scope(s): "
                + ", ".join(missing_scopes)
            )

    def _load_policy(self) -> Optional[AuthorizationPolicy]:
        if self._policy_or_provider is None:
            return None
        if isinstance(self._policy_or_provider, AuthorizationPolicy):
            return self._policy_or_provider
        try:
            return self._policy_or_provider.load_policy()
        except AuthorizationPolicyError:
            raise
        except Exception as exc:
            raise AuthorizationPolicyError(f"Failed to load authorization policy: {exc}") from exc


def _parse_policy(value: dict) -> AuthorizationPolicy:
    if not isinstance(value, dict):
        raise AuthorizationPolicyError("Authorization policy must be a JSON object.")
    version = value.get("version")
    if version != 1:
        raise AuthorizationPolicyError("Authorization policy version must be 1.")
    grants = value.get("grants")
    if not isinstance(grants, dict):
        raise AuthorizationPolicyError("Authorization policy grants must be an object.")

    normalized_grants: Dict[str, Dict[str, List[str]]] = {}
    for token_type, group_grants in grants.items():
        if not isinstance(group_grants, dict):
            raise AuthorizationPolicyError("Authorization policy token type grants must be objects.")
        normalized_grants[str(token_type)] = {}
        for group, scopes in group_grants.items():
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise AuthorizationPolicyError("Authorization policy scopes must be string lists.")
            normalized_grants[str(token_type)][str(group)] = normalize_unique_strings(scopes)

    return AuthorizationPolicy(version=1, grants=normalized_grants)


def _verify_signed_policy_envelope(envelope: Any, trusted_signers: List[Dict[str, str]], expected_domain_url: str, expected_environment: Optional[str], expected_tenant_id: Optional[str], now: datetime) -> None:
    if not isinstance(envelope, dict):
        raise AuthorizationPolicyError("Signed authorization policy envelope must be a JSON object.")
    if envelope.get("version") != 1:
        raise AuthorizationPolicyError("Signed authorization policy envelope version must be 1.")

    metadata = envelope.get("metadata")
    policy = envelope.get("policy")
    signature = envelope.get("signature")
    if not isinstance(metadata, dict) or not isinstance(policy, dict) or not isinstance(signature, str):
        raise AuthorizationPolicyError("Signed authorization policy envelope is missing required fields.")

    if str(metadata.get("domain_url", "")).rstrip("/") != expected_domain_url.rstrip("/"):
        raise AuthorizationPolicyError("Signed authorization policy domain binding does not match.")
    if expected_environment and metadata.get("environment") != expected_environment:
        raise AuthorizationPolicyError(
            "Signed authorization policy environment binding does not match."
        )
    if expected_tenant_id and metadata.get("tenant_id") != expected_tenant_id:
        raise AuthorizationPolicyError("Signed authorization policy tenant binding does not match.")
    _verify_policy_digest(metadata, policy)
    _verify_policy_time_window(metadata, now)

    signer = _find_trusted_signer(metadata, trusted_signers)
    payload = {key: value for key, value in envelope.items() if key != "signature"}
    signed_bytes = _canonical_json(payload)
    signature_bytes = _base64url_decode(signature)

    try:
        public_key = serialization.load_pem_public_key(signer["public_key_pem"].encode("utf-8"))
        public_key.verify(
            signature_bytes,
            signed_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise AuthorizationPolicyError("Signed authorization policy signature is invalid.") from exc
    except Exception as exc:
        raise AuthorizationPolicyError(f"Signed authorization policy could not be verified: {exc}") from exc


def _find_trusted_signer(metadata: Dict[str, Any], trusted_signers: List[Dict[str, str]]) -> Dict[str, str]:
    if metadata.get("signing_algorithm") != "SHA_256_RSA_PKCS_PSS":
        raise AuthorizationPolicyError("Signed authorization policy algorithm is unsupported.")
    for signer in trusted_signers:
        if (
            signer.get("key_id") == metadata.get("signing_key_id")
            and signer.get("key_version_id") == metadata.get("signing_key_version_id")
            and signer.get("algorithm") == metadata.get("signing_algorithm")
            and signer.get("public_key_pem")
        ):
            return signer
    raise AuthorizationPolicyError("Signed authorization policy signer is not trusted.")


def _verify_policy_digest(metadata: Dict[str, Any], policy: Dict[str, Any]) -> None:
    expected_digest = metadata.get("policy_digest")
    if not isinstance(expected_digest, str) or not expected_digest.startswith("sha256:"):
        raise AuthorizationPolicyError("Signed authorization policy digest is missing or malformed.")
    actual_digest = "sha256:" + hashlib.sha256(_canonical_json(policy)).hexdigest()
    if expected_digest != actual_digest:
        raise AuthorizationPolicyError("Signed authorization policy digest does not match.")


def _verify_policy_time_window(metadata: Dict[str, Any], now: datetime) -> None:
    issued_at = _parse_utc_datetime(metadata.get("issued_at"), "issued_at")
    not_after = _parse_utc_datetime(metadata.get("not_after"), "not_after")
    now_utc = _ensure_utc(now)
    if now_utc < issued_at:
        raise AuthorizationPolicyError("Signed authorization policy envelope is not yet valid.")
    if now_utc >= not_after:
        raise AuthorizationPolicyError("Signed authorization policy envelope is expired.")


def _parse_utc_datetime(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorizationPolicyError(f"Signed authorization policy {field_name} is missing.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationPolicyError(
            f"Signed authorization policy {field_name} is malformed."
        ) from exc
    return _ensure_utc(parsed)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _base64url_decode(value: str) -> bytes:
    padding_length = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding_length))


