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
    propagation_trust_claim: Optional[str] = None
    log_full_assertion: bool = False

    def __post_init__(self) -> None:
        if self.authz_policy_signature_mode not in {"off", "on"}:
            raise ValueError(
                "authz_policy_signature_mode must be 'off' or 'on'"
            )

    @classmethod
    def from_env(
        cls,
        config_overrides: Optional[Dict[str, Any]] = None,
    ) -> "TokenFactoryRuntimeConfig":
        def value(name: str, default: Optional[Any] = None) -> Optional[Any]:
            if config_overrides and name in config_overrides:
                return config_overrides[name]
            return os.getenv(name, default)

        domain_url = str(value("TOKEN_FACTORY_DOMAIN_URL", "")).rstrip("/")
        domain_region = str(value("TOKEN_FACTORY_DOMAIN_REGION", ""))
        timeout_raw = value("TOKEN_FACTORY_TIMEOUT_SECONDS", "30")
        try:
            timeout_seconds = int(timeout_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"TOKEN_FACTORY_TIMEOUT_SECONDS must be an integer, got '{timeout_raw}'"
            ) from exc
        signature_mode = str(
            value("TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE", "off") or "off"
        ).strip()
        if signature_mode not in {"off", "on"}:
            raise ValueError(
                "TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE must be 'off' or 'on'"
            )

        return cls(
            domain_url=domain_url,
            domain_region=domain_region,
            timeout_seconds=timeout_seconds,
            oci_auth_mode=str(value("TOKEN_FACTORY_OCI_AUTH_MODE", "instance-principal")),
            oci_auth_profile=str(value("TOKEN_FACTORY_OCI_AUTH_PROFILE", "DEFAULT") or "DEFAULT"),
            oci_region=(
                str(value("TOKEN_FACTORY_OCI_REGION"))
                if value("TOKEN_FACTORY_OCI_REGION")
                else None
            ),
            subject_claim=str(value("TOKEN_FACTORY_SUBJECT_CLAIM", "sub") or "sub"),
            groups_claim=str(value("TOKEN_FACTORY_GROUPS_CLAIM", "groups") or "groups"),
            authz_policy_enable=_coerce_bool(
                value("TOKEN_FACTORY_AUTHZ_POLICY_ENABLE", False)
            ),
            authz_policy_secret_ocid=(
                str(value("TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID"))
                if value("TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID")
                else None
            ),
            authz_policy_signature_mode=signature_mode,
            authz_trusted_signers=_parse_trusted_signers(
                value("TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON")
            ),
            authz_policy_environment=(
                str(value("TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT"))
                if value("TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT")
                else None
            ),
            authz_policy_tenant_id=(
                str(value("TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID"))
                if value("TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID")
                else None
            ),
            propagation_trust_claim=(
                str(value("TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM"))
                if value("TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM")
                else None
            ),
            log_full_assertion=_coerce_bool(value("TOKEN_FACTORY_LOG_FULL_ASSERTION", False)),
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
            propagation_trust_claim=config.propagation_trust_claim,
            log_full_assertion=config.log_full_assertion,
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
            raise ValueError("TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON must be valid JSON") from exc
    if not isinstance(signers, list) or not all(isinstance(signer, dict) for signer in signers):
        raise ValueError("TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON must be a JSON array of objects")
    return signers
