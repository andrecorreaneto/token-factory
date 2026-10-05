import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "register_kms_certificate.py"
SPEC = importlib.util.spec_from_file_location("register_kms_certificate", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class KmsCertificateTests(unittest.TestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key_pem = self.private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def test_builds_self_signed_certificate_with_external_signer(self):
        certificate_pem = MODULE.build_self_signed_certificate(self.public_key_pem, "orders-api", lambda value: self.private_key.sign(value, padding.PKCS1v15(), hashes.SHA256()), datetime(2026, 1, 1, tzinfo=timezone.utc))
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))

        self.private_key.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, "orders-api")

    def test_rejects_certificate_for_different_kms_public_key(self):
        certificate_pem = MODULE.build_self_signed_certificate(self.public_key_pem, "orders-api", lambda value: self.private_key.sign(value, padding.PKCS1v15(), hashes.SHA256()), datetime(2026, 1, 1, tzinfo=timezone.utc))
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_public_pem = other_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

        with self.assertRaisesRegex(RuntimeError, "public key does not match"):
            MODULE.verify_certificate_public_key(certificate_pem, other_public_pem)

    def test_registration_reuses_identical_alias(self):
        client = Mock()
        client.list_o_auth_partner_certificates.return_value.data.resources = [SimpleNamespace(id="certificate-id", x509_base64_certificate="certificate")]

        certificate_id = MODULE.register_certificate(client, "orders-v1", "certificate")

        self.assertEqual(certificate_id, "certificate-id")
        client.create_o_auth_partner_certificate.assert_not_called()

    def test_registration_rejects_alias_with_different_certificate(self):
        client = Mock()
        client.list_o_auth_partner_certificates.return_value.data.resources = [SimpleNamespace(id="certificate-id", x509_base64_certificate="different")]

        with self.assertRaisesRegex(RuntimeError, "already exists with different public material"):
            MODULE.register_certificate(client, "orders-v1", "certificate")

    def test_registration_creates_missing_alias_with_sdk_model(self):
        client = Mock()
        client.list_o_auth_partner_certificates.return_value.data.resources = []
        client.create_o_auth_partner_certificate.return_value.data.id = "certificate-id"

        certificate_id = MODULE.register_certificate(client, "orders-v1", "certificate")

        self.assertEqual(certificate_id, "certificate-id")
        details = client.create_o_auth_partner_certificate.call_args.kwargs["o_auth_partner_certificate"]
        self.assertEqual(details.certificate_alias, "orders-v1")
        self.assertEqual(details.x509_base64_certificate, "certificate")
        self.assertEqual(details.schemas, [MODULE.SCHEMA])

    def test_explicit_rotation_retirement_deletes_alias(self):
        client = Mock()
        client.list_o_auth_partner_certificates.return_value.data.resources = [SimpleNamespace(id="certificate-id")]

        deleted = MODULE.delete_certificate(client, "orders-v1")

        self.assertTrue(deleted)
        client.delete_o_auth_partner_certificate.assert_called_once_with("certificate-id")

    def test_rejects_alias_that_can_escape_scim_filter(self):
        with self.assertRaisesRegex(RuntimeError, "Certificate alias"):
            MODULE.validate_alias('orders" or id pr')

    def test_explicit_oci_config_uses_terraform_runner_credentials(self):
        environment = {
            "TF_CERT_OCI_TENANCY_OCID": "ocid1.tenancy.oc1..test",
            "TF_CERT_OCI_USER_OCID": "ocid1.user.oc1..test",
            "TF_CERT_OCI_FINGERPRINT": "aa:bb:cc",
            "TF_CERT_OCI_PRIVATE_KEY_PATH": "C:/keys/test.pem",
            "TF_CERT_OCI_PRIVATE_KEY_PASSWORD": "secret",
            "TF_CERT_OCI_REGION": "us-chicago-1",
        }

        with patch.dict(MODULE.os.environ, environment, clear=True), patch.object(MODULE.oci.config, "validate_config") as validate_config, patch.object(MODULE.oci.config, "from_file") as from_file:
            config, signer = MODULE._oci_config_and_signer()

        self.assertIsNone(signer)
        self.assertEqual(config, {"tenancy": "ocid1.tenancy.oc1..test", "user": "ocid1.user.oc1..test", "fingerprint": "aa:bb:cc", "key_file": "C:/keys/test.pem", "pass_phrase": "secret", "region": "us-chicago-1"})
        validate_config.assert_called_once_with(config)
        from_file.assert_not_called()

    def test_explicit_oci_config_rejects_partial_credentials(self):
        environment = {"TF_CERT_OCI_USER_OCID": "ocid1.user.oc1..test"}

        with patch.dict(MODULE.os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Explicit certificate-utility OCI authentication requires"):
                MODULE._oci_config_and_signer()

    def test_kms_management_client_omits_null_signer_for_api_key_config(self):
        config = {"region": "us-chicago-1"}
        key_version = object()
        client = Mock()
        client.get_key_version.return_value.data = key_version

        with patch.object(MODULE, "_oci_config_and_signer", return_value=(config, None)), patch.object(MODULE, "KmsManagementClient", return_value=client) as client_type:
            result = MODULE.get_key_version("key-id", "version-id", "https://management.example")

        self.assertIs(result, key_version)
        client_type.assert_called_once_with(config, service_endpoint="https://management.example")

    def test_kms_crypto_client_omits_null_signer_for_api_key_config(self):
        config = {"region": "us-chicago-1"}
        client = Mock()
        client.sign.return_value.data.signature = MODULE.base64.b64encode(b"signature").decode("ascii")
        message = b"x" * 520

        with patch.object(MODULE, "_oci_config_and_signer", return_value=(config, None)), patch.object(MODULE, "KmsCryptoClient", return_value=client) as client_type:
            signature = MODULE.kms_sign(message, "key-id", "version-id", "https://crypto.example")

        self.assertEqual(signature, b"signature")
        client_type.assert_called_once_with(config, service_endpoint="https://crypto.example")
        details = client.sign.call_args.args[0]
        self.assertEqual(details.message_type, "DIGEST")
        self.assertEqual(MODULE.base64.b64decode(details.message), MODULE.hashlib.sha256(message).digest())

    def test_identity_domains_client_omits_null_signer_for_api_key_config(self):
        config = {"region": "us-chicago-1"}

        with patch.object(MODULE, "_oci_config_and_signer", return_value=(config, None)), patch.object(MODULE, "IdentityDomainsClient") as client_type:
            MODULE.get_identity_domains_client("https://identity.example")

        client_type.assert_called_once_with(config, service_endpoint="https://identity.example")
