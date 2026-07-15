from __future__ import annotations

import base64
import importlib.util
import time
from pathlib import Path
import sys
import types
import unittest


class _FakeJwt(types.ModuleType):
    def decode(self, *_args, **_kwargs):
        return {"exp": int(time.time()) + 1800}

    def encode(self, *_args, **_kwargs):
        return "signed.assertion"


sys.modules.setdefault("jwt", _FakeJwt("jwt"))
requests_module = types.ModuleType("requests")


class _FakeDiscoveryResponse:
    ok = True
    status_code = 200
    text = "{}"

    def json(self):
        return {
            "issuer": "https://issuer.example.com/",
            "jwks_uri": "https://issuer.example.com/jwks",
        }


requests_module.get = lambda *_args, **_kwargs: _FakeDiscoveryResponse()
sys.modules.setdefault("requests", requests_module)
sys.modules.setdefault("oci", types.ModuleType("oci"))
sys.modules.setdefault("oci.auth", types.ModuleType("oci.auth"))
signers_module = types.ModuleType("oci.auth.signers")
signers_module.TokenExchangeSigner = object
signers_module.InstancePrincipalsSecurityTokenSigner = object
signers_module.get_resource_principals_signer = lambda: object()
sys.modules.setdefault("oci.auth.signers", signers_module)
oci_config_module = types.ModuleType("oci.config")
oci_config_module.from_file = lambda *_args, **_kwargs: {}
sys.modules.setdefault("oci.config", oci_config_module)
identity_data_plane_module = types.ModuleType("oci.identity_data_plane")
identity_data_plane_module.DataplaneClient = object
sys.modules.setdefault("oci.identity_data_plane", identity_data_plane_module)
identity_data_plane_models_module = types.ModuleType("oci.identity_data_plane.models")
identity_data_plane_models_module.GenerateScopedAccessTokenDetails = object
sys.modules.setdefault("oci.identity_data_plane.models", identity_data_plane_models_module)
secrets_module = types.ModuleType("oci.secrets")
secrets_module.SecretsClient = object
sys.modules.setdefault("oci.secrets", secrets_module)
signer_module = types.ModuleType("oci.signer")
signer_module.Signer = object
sys.modules.setdefault("oci.signer", signer_module)

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "token_factory",
    ROOT / "__init__.py",
    submodule_search_locations=[str(ROOT)],
)
token_factory_package = importlib.util.module_from_spec(spec)
sys.modules["token_factory"] = token_factory_package
assert spec.loader is not None
spec.loader.exec_module(token_factory_package)

from token_factory import TokenFactory
from token_factory._factory_support import ConfigurationError
from token_factory._oauth_client_resolution import OAuthClientInfo


PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEI00000000000000000000000000000000000000000
-----END PRIVATE KEY-----"""


class TokenFactoryOracleDatabaseSelectorChecks(unittest.TestCase):
    def test_oci_principal_selector_uses_factory_signer_without_assertion_validation(self):
        calls = []

        def db_token_generator(signer, public_key_pem, scope, config):
            calls.append((signer, public_key_pem, scope, config.oci_auth_mode))
            return "header.payload.signature"

        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs-example.identity.oraclecloud.com",
                "domain_region": "us-ashburn-1",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "MCP_SERVER": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
            factory_oci_signer_builder=lambda _config: "factory-signer",
            db_token_generator=db_token_generator,
        )
        token_factory._validate_assertion = lambda *_args, **_kwargs: self.fail(
            "OCI_PRINCIPAL must not validate a caller assertion"
        )

        result = token_factory.get_token(
            "oracle-database",
            "oci_principal",
            "urn:oracle:db::id::*",
            client_key="MCP_SERVER",
        )

        self.assertEqual(result[0], "header.payload.signature")
        self.assertIn("PRIVATE KEY", result[1])
        self.assertEqual(result.principal_mode, "oci_principal")
        self.assertGreater(result.expires_at_epoch, int(time.time()))
        self.assertEqual(calls[0][0], "factory-signer")
        self.assertIn("BEGIN PUBLIC KEY", calls[0][1])
        self.assertEqual(calls[0][2], "urn:oracle:db::id::*")
        self.assertEqual(calls[0][3], "instance-principal")

    def test_oci_principal_selector_rejects_oci_profile_mode(self):
        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs-example.identity.oraclecloud.com",
                "domain_region": "us-ashburn-1",
                "oci_auth_mode": "oci-profile",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "MCP_SERVER": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
            factory_oci_signer_builder=lambda _config: "factory-signer",
            db_token_generator=lambda *_args: "header.payload.signature",
        )

        with self.assertRaises(ConfigurationError):
            token_factory.get_token(
                "oracle-database",
                "OCI_PRINCIPAL",
                "urn:oracle:db::id::*",
                client_key="MCP_SERVER",
            )

    def test_process_selector_is_reserved(self):
        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs-example.identity.oraclecloud.com",
                "domain_region": "us-ashburn-1",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "MCP_SERVER": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
        )

        with self.assertRaises(NotImplementedError):
            token_factory.get_token(
                "oracle-database",
                "PROCESS",
                "urn:oracle:db::id::*",
                client_key="MCP_SERVER",
            )

    def test_existing_token_type_second_user_path_still_works(self):
        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs-example.identity.oraclecloud.com",
                "domain_region": "us-ashburn-1",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "MCP_SERVER": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
            token_exchange_signer_cls=lambda *_args, **_kwargs: "upst-signer",
            signer_keypair_extractor=lambda _signer: (
                "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----",
                "private-key",
            ),
            db_token_generator=lambda *_args: "header.payload.signature",
        )
        token_factory._validate_assertion = lambda _credential, _client_key: {
            "hosting_component": token_factory._resolve_hosting_component("MCP_SERVER"),
            "subject": "user@example.com",
            "groups": [],
        }

        result = token_factory.get_token(
            "caller.jwt.assertion",
            "oracle-database",
            "urn:oracle:db::id::*",
            client_key="MCP_SERVER",
        )

        self.assertEqual(result[0], "header.payload.signature")
        self.assertEqual(result[1], "private-key")
        self.assertEqual(result.principal_mode, "user")

    def test_missing_scope_fails_for_oci_principal(self):
        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs-example.identity.oraclecloud.com",
                "domain_region": "us-ashburn-1",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "MCP_SERVER": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
        )

        with self.assertRaises(ValueError):
            token_factory.get_token(
                "oracle-database",
                "OCI_PRINCIPAL",
                client_key="MCP_SERVER",
            )


if __name__ == "__main__":
    unittest.main()
