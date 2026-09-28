#!/usr/bin/env python3
"""Generate, verify, and register KMS-backed OAuth partner certificates."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import secrets

from asn1crypto import algos, core, keys, pem, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import oci
from oci.identity_domains import IdentityDomainsClient
from oci.identity_domains.models import OAuthPartnerCertificate
from oci.key_management import KmsCryptoClient, KmsManagementClient
from oci.key_management.models import SignDataDetails


SCHEMA = "urn:ietf:params:scim:schemas:oracle:idcs:OAuthPartnerCertificate"
SIGNING_ALGORITHM = "SHA_256_RSA_PKCS1_V1_5"
ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_alias(alias: str) -> str:
    """Reject aliases that are unsafe in an Identity Domains SCIM filter."""
    if not ALIAS_PATTERN.fullmatch(alias):
        raise RuntimeError("Certificate alias must use only letters, digits, dot, underscore, and hyphen.")
    return alias


def _asn1_time(value: datetime) -> asn1_x509.Time:
    normalized = value.astimezone(timezone.utc)
    if normalized.year < 2050:
        return asn1_x509.Time({"utc_time": core.UTCTime(normalized)})
    return asn1_x509.Time({"general_time": core.GeneralizedTime(normalized)})


def build_self_signed_certificate(public_key_pem: str, common_name: str, sign_callback, now: datetime | None = None) -> str:
    """Build an RSA SHA-256 self-signed certificate using an external signer."""
    issued_at = now or datetime.now(timezone.utc)
    _type_name, _headers, public_key_der = pem.unarmor(public_key_pem.encode("ascii"))
    public_key_info = keys.PublicKeyInfo.load(public_key_der)
    name = asn1_x509.Name.build({"common_name": common_name, "organization_name": "Token Factory"})
    signature_algorithm = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    extensions = [
        asn1_x509.Extension({"extn_id": "basic_constraints", "critical": True, "extn_value": asn1_x509.BasicConstraints({"ca": False})}),
        asn1_x509.Extension({"extn_id": "key_usage", "critical": True, "extn_value": asn1_x509.KeyUsage({"digital_signature"})}),
    ]
    tbs_certificate = asn1_x509.TbsCertificate({
        "version": "v3",
        "serial_number": secrets.randbits(159),
        "signature": signature_algorithm,
        "issuer": name,
        "validity": asn1_x509.Validity({"not_before": _asn1_time(issued_at - timedelta(minutes=5)), "not_after": _asn1_time(issued_at + timedelta(days=365))}),
        "subject": name,
        "subject_public_key_info": public_key_info,
        "extensions": extensions,
    })
    signature = sign_callback(tbs_certificate.dump())
    certificate = asn1_x509.Certificate({"tbs_certificate": tbs_certificate, "signature_algorithm": signature_algorithm, "signature_value": signature})
    return pem.armor("CERTIFICATE", certificate.dump()).decode("ascii")


def verify_certificate_public_key(certificate_pem: str, public_key_pem: str) -> None:
    """Fail when a certificate does not contain the selected KMS public key."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    certificate_key = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kms_key = serialization.load_pem_public_key(public_key_pem.encode("ascii")).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if certificate_key != kms_key:
        raise RuntimeError("Certificate public key does not match the selected OCI KMS key version.")


def certificate_der_base64(certificate_pem: str) -> str:
    """Return a PEM certificate as the base64 DER value expected by Identity Domains."""
    _type_name, _headers, certificate_der = pem.unarmor(certificate_pem.encode("ascii"))
    return base64.b64encode(certificate_der).decode("ascii")


def get_identity_domains_client(endpoint: str) -> IdentityDomainsClient:
    """Create an Identity Domains client using the bootstrap runner OCI identity."""
    config, signer = _oci_config_and_signer()
    return IdentityDomainsClient(config, service_endpoint=endpoint, **_signer_arguments(signer))


def find_certificate(client: IdentityDomainsClient, alias: str) -> object | None:
    """Find one OAuth partner certificate by its validated alias."""
    alias = validate_alias(alias)
    response = client.list_o_auth_partner_certificates(filter=f'certificateAlias eq "{alias}"', count=1)
    resources = response.data.resources or []
    return resources[0] if resources else None


def register_certificate(client: IdentityDomainsClient, alias: str, certificate: str) -> str:
    """Create the OAuth partner certificate or verify the existing alias is identical."""
    alias = validate_alias(alias)
    existing = find_certificate(client, alias)
    if existing:
        if existing.x509_base64_certificate != certificate:
            raise RuntimeError(f"Identity Domains certificate alias '{alias}' already exists with different public material.")
        return str(existing.id)
    details = OAuthPartnerCertificate(schemas=[SCHEMA], certificate_alias=alias, x509_base64_certificate=certificate)
    return str(client.create_o_auth_partner_certificate(o_auth_partner_certificate=details).data.id)


def delete_certificate(client: IdentityDomainsClient, alias: str) -> bool:
    """Delete a registered certificate alias when explicitly retiring a rotated key version."""
    alias = validate_alias(alias)
    existing = find_certificate(client, alias)
    if not existing:
        return False
    client.delete_o_auth_partner_certificate(str(existing.id))
    return True


def _explicit_oci_config_from_env() -> dict | None:
    """Build the OCI SDK config from the same API-key inputs used by Terraform."""
    values = {
        "tenancy": os.getenv("TF_CERT_OCI_TENANCY_OCID", "").strip(),
        "user": os.getenv("TF_CERT_OCI_USER_OCID", "").strip(),
        "fingerprint": os.getenv("TF_CERT_OCI_FINGERPRINT", "").strip(),
        "key_file": os.getenv("TF_CERT_OCI_PRIVATE_KEY_PATH", "").strip(),
        "region": os.getenv("TF_CERT_OCI_REGION", "").strip(),
    }
    if not any(values[name] for name in ("user", "fingerprint", "key_file")):
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Explicit certificate-utility OCI authentication requires: {', '.join(missing)}.")
    pass_phrase = os.getenv("TF_CERT_OCI_PRIVATE_KEY_PASSWORD", "")
    if pass_phrase:
        values["pass_phrase"] = pass_phrase
    oci.config.validate_config(values)
    return values


def _oci_config_and_signer() -> tuple[dict, object | None]:
    mode = os.getenv("TF_CERT_OCI_AUTH_MODE", "oci-profile").strip().lower()
    if mode == "instance-principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {"region": signer.region}, signer
    if mode == "resource-principal":
        signer = oci.auth.signers.get_resource_principals_signer()
        return {"region": getattr(signer, "region", os.getenv("OCI_RESOURCE_PRINCIPAL_REGION"))}, signer
    if mode == "oke-workload-identity":
        signer = oci.auth.signers.get_oke_workload_identity_resource_principal_signer()
        return {"region": getattr(signer, "region", os.getenv("OCI_RESOURCE_PRINCIPAL_REGION"))}, signer
    if mode != "oci-profile":
        raise RuntimeError("TF_CERT_OCI_AUTH_MODE must be oci-profile, instance-principal, resource-principal, or oke-workload-identity.")
    explicit_config = _explicit_oci_config_from_env()
    if explicit_config is not None:
        return explicit_config, None
    return oci.config.from_file(profile_name=os.getenv("TF_CERT_OCI_AUTH_PROFILE", "DEFAULT")), None


def _signer_arguments(signer: object | None) -> dict:
    """Omit signer for API-key config so the OCI SDK constructs its default signer."""
    return {} if signer is None else {"signer": signer}


def get_key_version(key_id: str, key_version_id: str, management_endpoint: str) -> object:
    config, signer = _oci_config_and_signer()
    client = KmsManagementClient(config, service_endpoint=management_endpoint, **_signer_arguments(signer))
    return client.get_key_version(key_id, key_version_id).data


def kms_sign(message: bytes, key_id: str, key_version_id: str, crypto_endpoint: str) -> bytes:
    config, signer = _oci_config_and_signer()
    client = KmsCryptoClient(config, service_endpoint=crypto_endpoint, **_signer_arguments(signer))
    digest = hashlib.sha256(message).digest()
    details = SignDataDetails(message=base64.b64encode(digest).decode("ascii"), key_id=key_id, key_version_id=key_version_id, message_type="DIGEST", signing_algorithm=SIGNING_ALGORITHM)
    return base64.b64decode(client.sign(details).data.signature)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required.")
    return value


def run_from_env() -> dict[str, str]:
    action = _required_env("TF_CERT_ACTION")
    if action == "delete":
        client = get_identity_domains_client(_required_env("TF_CERT_IDCS_ENDPOINT"))
        deleted = delete_certificate(client, _required_env("TF_CERT_ALIAS"))
        return {"deleted": str(deleted).lower()}
    key_id = _required_env("TF_CERT_KMS_KEY_ID")
    key_version_id = _required_env("TF_CERT_KMS_KEY_VERSION_ID")
    management_endpoint = _required_env("TF_CERT_KMS_MANAGEMENT_ENDPOINT")
    key_version = get_key_version(key_id, key_version_id, management_endpoint)
    public_key_pem = str(key_version.public_key)

    if action == "verify":
        certificate_pem = base64.b64decode(_required_env("TF_CERT_PEM_BASE64")).decode("utf-8")
        verify_certificate_public_key(certificate_pem, public_key_pem)
        return {"key_id": key_id, "key_version_id": key_version_id, "public_key_sha256": hashlib.sha256(public_key_pem.encode("ascii")).hexdigest()}
    if action != "generate-register":
        raise RuntimeError("TF_CERT_ACTION must be verify, generate-register, or delete.")

    endpoint = _required_env("TF_CERT_IDCS_ENDPOINT")
    client = get_identity_domains_client(endpoint)
    alias = _required_env("TF_CERT_ALIAS")
    existing = find_certificate(client, alias)
    if existing:
        certificate_der = base64.b64decode(existing.x509_base64_certificate)
        certificate_pem = pem.armor("CERTIFICATE", certificate_der).decode("ascii")
        verify_certificate_public_key(certificate_pem, public_key_pem)
        return {"certificate_id": str(existing.id), "certificate_sha256": hashlib.sha256(certificate_der).hexdigest()}

    crypto_endpoint = _required_env("TF_CERT_KMS_CRYPTO_ENDPOINT")
    certificate_pem = build_self_signed_certificate(public_key_pem, _required_env("TF_CERT_COMMON_NAME"), lambda value: kms_sign(value, key_id, key_version_id, crypto_endpoint))
    verify_certificate_public_key(certificate_pem, public_key_pem)
    certificate = certificate_der_base64(certificate_pem)
    certificate_id = register_certificate(client, alias, certificate)
    return {"certificate_id": certificate_id, "certificate_sha256": hashlib.sha256(base64.b64decode(certificate)).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-env", action="store_true", required=True)
    parser.parse_args()
    print(json.dumps(run_from_env(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
