import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class TokenFactoryRuntimeConfig:
    domain_url: str
    domain_region: str
    timeout_seconds: int = 30
    oci_auth_mode: str = "instance-principal"
    oci_auth_profile: str = "DEFAULT"
    oci_region: Optional[str] = None
    subject_claim: str = "sub"
    groups_claim: str = "groups"
    authz_policy_enable: bool = False
    authz_policy_secret_ocid: Optional[str] = None
    authz_policy_signature_mode: str = "off"
    authz_trusted_signers: Optional[list[dict]] = None
    authz_policy_environment: Optional[str] = None
    authz_policy_tenant_id: Optional[str] = None
    log_full_assertion: bool = False
    cache_enable: bool = False
    cache_max_size: int = 1024

    def __post_init__(self) -> None:
        if self.authz_policy_signature_mode not in {"off", "on"}:
            raise ValueError(
                "authz_policy_signature_mode must be 'off' or 'on'"
            )
        if self.cache_max_size < 1:
            raise ValueError("cache_max_size must be greater than or equal to 1")

    @classmethod
    def from_env(cls, config_overrides: Optional[Dict[str, Any]] = None) -> "TokenFactoryRuntimeConfig":
        def value(name: str, default: Optional[Any] = None) -> Optional[Any]:
            if config_overrides and name in config_overrides:
                return config_overrides[name]
            return os.getenv(name, default)

        domain_url = str(value("TF_SHARED_DOMAIN_URL", "")).rstrip("/")
        domain_region = str(value("TF_SHARED_DOMAIN_REGION", ""))
        timeout_raw = value("TF_SHARED_TIMEOUT_SECONDS", "30")
        try:
            timeout_seconds = int(timeout_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"TF_SHARED_TIMEOUT_SECONDS must be an integer, got '{timeout_raw}'"
            ) from exc
        cache_max_size_raw = value("TF_SHARED_CACHE_MAX_SIZE", "1024") or "1024"
        try:
            cache_max_size = int(cache_max_size_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"TF_SHARED_CACHE_MAX_SIZE must be an integer, got '{cache_max_size_raw}'"
            ) from exc
        signature_mode = str(
            value("TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE", "off") or "off"
        ).strip()
        if signature_mode not in {"off", "on"}:
            raise ValueError(
                "TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE must be 'off' or 'on'"
            )

        return cls(
            domain_url=domain_url,
            domain_region=domain_region,
            timeout_seconds=timeout_seconds,
            oci_auth_mode=str(value("TF_SHARED_OCI_AUTH_MODE", "instance-principal")),
            oci_auth_profile=str(value("TF_SHARED_OCI_AUTH_PROFILE", "DEFAULT") or "DEFAULT"),
            oci_region=(
                str(value("TF_SHARED_OCI_REGION"))
                if value("TF_SHARED_OCI_REGION")
                else None
            ),
            subject_claim=str(value("TF_SHARED_SUBJECT_CLAIM", "sub") or "sub"),
            groups_claim=str(value("TF_SHARED_GROUPS_CLAIM", "groups") or "groups"),
            authz_policy_enable=_coerce_bool(
                value("TF_SHARED_AUTHZ_POLICY_ENABLE", False)
            ),
            authz_policy_secret_ocid=(
                str(value("TF_SHARED_AUTHZ_POLICY_SECRET_OCID"))
                if value("TF_SHARED_AUTHZ_POLICY_SECRET_OCID")
                else None
            ),
            authz_policy_signature_mode=signature_mode,
            authz_trusted_signers=_parse_trusted_signers(
                value("TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON")
            ),
            authz_policy_environment=(
                str(value("TF_SHARED_AUTHZ_POLICY_ENVIRONMENT"))
                if value("TF_SHARED_AUTHZ_POLICY_ENVIRONMENT")
                else None
            ),
            authz_policy_tenant_id=(
                str(value("TF_SHARED_AUTHZ_POLICY_TENANT_ID"))
                if value("TF_SHARED_AUTHZ_POLICY_TENANT_ID")
                else None
            ),
            log_full_assertion=_coerce_bool(value("TF_SHARED_LOG_FULL_ASSERTION", False)),
            cache_enable=_coerce_bool(value("TF_SHARED_CACHE_ENABLE", False)),
            cache_max_size=cache_max_size,
        )

    @classmethod
    def from_legacy_config(cls, config: Any) -> "TokenFactoryRuntimeConfig":
        return cls(
            domain_url=config.domain_url,
            domain_region=config.domain_oci_region,
            timeout_seconds=config.token_factory_timeout,
            oci_auth_mode=config.oci_auth_mode,
            oci_auth_profile=config.oci_auth_profile or "DEFAULT",
            oci_region=config.assertion_oci_region,
            log_full_assertion=config.log_full_assertion,
            cache_enable=getattr(config, "cache_enable", False),
            cache_max_size=getattr(config, "cache_max_size", 1024),
        )


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_trusted_signers(value: Any) -> list[dict]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        signers = value
    else:
        try:
            signers = json.loads(str(value))
        except json.JSONDecodeError as exc:
            raise ValueError("TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON must be valid JSON") from exc
    if not isinstance(signers, list) or not all(isinstance(signer, dict) for signer in signers):
        raise ValueError("TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON must be a JSON array of objects")
    return signers
