from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ._errors import OAuthClientResolutionError
from ._factory_support import (
    _fetch_secret_value_from_oci,
    _parse_token_factory_credentials,
)
from ._normalization import normalize_unique_strings
from ._runtime_config import TokenFactoryRuntimeConfig


@dataclass(frozen=True)
class OAuthClientInfo:
    client_credentials: Optional[str] = None
    client_credentials_secret_ocid: Optional[str] = None
    issuer: Optional[str] = None
    kid: Optional[str] = None
    kms_key_id: Optional[str] = None
    kms_key_version_id: Optional[str] = None
    kms_crypto_endpoint: Optional[str] = None
    propagation_trust_claim: Optional[str] = None
    resource_audiences: List[str] = field(default_factory=list)
    required_incoming_scopes: List[str] = field(default_factory=list)
    # None disables the client check; a list (even empty) enables it, and the hosting app's own client ID is always allowed.
    allowed_client_ids: Optional[List[str]] = None


@dataclass(frozen=True)
class OAuthClientIdentity:
    client_id: str
    client_secret: str
    issuer: Optional[str] = None
    kid: Optional[str] = None
    kms_key_id: Optional[str] = None
    kms_key_version_id: Optional[str] = None
    kms_crypto_endpoint: Optional[str] = None


@dataclass(frozen=True)
class ResolvedHostingComponent:
    client_key: str
    oauth_identity: OAuthClientIdentity
    resource_audiences: List[str]
    propagation_trust_claim: Optional[str] = None
    required_incoming_scopes: List[str] = field(default_factory=list)
    allowed_client_ids: Optional[List[str]] = None


class OAuthClientResolver:
    def resolve(self, client_key: Optional[str], *, require_signing_material: bool = True) -> ResolvedHostingComponent:
        raise NotImplementedError


class StaticOAuthClientResolver(OAuthClientResolver):
    def __init__(self, client_info: Dict[str, OAuthClientInfo]):
        self._client_info = dict(client_info)

    def resolve(self, client_key: Optional[str], *, require_signing_material: bool = True) -> ResolvedHostingComponent:
        selected_client_key, info = self._select_client_info(client_key)
        return self._resolve_info(selected_client_key, info, None, require_signing_material)

    def _select_client_info(self, client_key: Optional[str]) -> tuple[str, OAuthClientInfo]:
        if isinstance(client_key, str) and client_key.strip():
            selected_client_key = client_key.strip()
            if selected_client_key not in self._client_info:
                raise OAuthClientResolutionError(
                    f"Unknown client_key '{selected_client_key}'."
                )
            return selected_client_key, self._client_info[selected_client_key]

        raise OAuthClientResolutionError(
            "client_key is required."
        )

    def _resolve_info(self, client_key: str, info: OAuthClientInfo, secret_reader: Optional[Callable[[str], str]], require_signing_material: bool) -> ResolvedHostingComponent:
        client_id, client_secret = _parse_token_factory_credentials(
            _resolve_required_value(
                direct_value=info.client_credentials,
                secret_ocid=info.client_credentials_secret_ocid,
                secret_reader=secret_reader,
                label="client credentials",
            ),
            "client credentials",
        )
        if require_signing_material and not info.issuer:
            raise OAuthClientResolutionError(f"OAuth client '{client_key}' is missing issuer.")

        return ResolvedHostingComponent(
            client_key=client_key,
            oauth_identity=OAuthClientIdentity(
                client_id=client_id,
                client_secret=client_secret,
                issuer=info.issuer,
                kid=info.kid,
                kms_key_id=info.kms_key_id,
                kms_key_version_id=info.kms_key_version_id,
                kms_crypto_endpoint=info.kms_crypto_endpoint,
            ),
            resource_audiences=list(info.resource_audiences),
            propagation_trust_claim=info.propagation_trust_claim,
            required_incoming_scopes=list(info.required_incoming_scopes),
            allowed_client_ids=None if info.allowed_client_ids is None else normalize_unique_strings(info.allowed_client_ids),
        )


class VaultOAuthClientResolver(StaticOAuthClientResolver):
    def __init__(self, client_info: Dict[str, OAuthClientInfo], secret_reader: Optional[Callable[[str], str]] = None, runtime_config: Optional[TokenFactoryRuntimeConfig] = None):
        super().__init__(client_info)
        self._secret_reader = secret_reader
        self._runtime_config = runtime_config

    def resolve(self, client_key: Optional[str], *, require_signing_material: bool = True) -> ResolvedHostingComponent:
        selected_client_key, info = self._select_client_info(client_key)
        return self._resolve_info(
            selected_client_key,
            info,
            self._read_secret,
            require_signing_material,
        )

    def _read_secret(self, secret_ocid: str) -> str:
        if self._secret_reader:
            return self._secret_reader(secret_ocid)
        config = self._runtime_config
        if config is None:
            raise OAuthClientResolutionError(
                "VaultOAuthClientResolver requires secret_reader or runtime_config."
            )
        region = getattr(config, "oci_region", None)
        return _fetch_secret_value_from_oci(secret_ocid, region, config)


def _resolve_required_value(*, direct_value: Optional[str], secret_ocid: Optional[str], secret_reader: Optional[Callable[[str], str]], label: str) -> str:
    value = _resolve_optional_value(
        direct_value=direct_value,
        secret_ocid=secret_ocid,
        secret_reader=secret_reader,
    )
    if value is None or value == "":
        raise OAuthClientResolutionError(f"OAuth client is missing {label}.")
    return value


def _resolve_optional_value(*, direct_value: Optional[str], secret_ocid: Optional[str], secret_reader: Optional[Callable[[str], str]]) -> Optional[str]:
    if secret_ocid:
        if not secret_reader:
            raise OAuthClientResolutionError("Secret OCID configured but no secret reader is available.")
        return secret_reader(secret_ocid)
    return direct_value


def _read_text_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
