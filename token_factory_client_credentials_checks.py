from __future__ import annotations

import base64
import importlib.util
from pathlib import Path
import sys
import types
import unittest


class _FakeJwt(types.ModuleType):
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
cryptography_module = types.ModuleType("cryptography")
cryptography_module.x509 = types.ModuleType("cryptography.x509")
cryptography_module.x509.Certificate = object
cryptography_exceptions_module = types.ModuleType("cryptography.exceptions")
cryptography_exceptions_module.InvalidSignature = type("InvalidSignature", (Exception,), {})
hazmat_module = types.ModuleType("cryptography.hazmat")
primitives_module = types.ModuleType("cryptography.hazmat.primitives")
hashes_module = types.ModuleType("cryptography.hazmat.primitives.hashes")
serialization_module = types.ModuleType("cryptography.hazmat.primitives.serialization")
asymmetric_module = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
padding_module = types.ModuleType("cryptography.hazmat.primitives.asymmetric.padding")
backends_module = types.ModuleType("cryptography.hazmat.backends")
backends_module.default_backend = lambda: object()
sys.modules.setdefault("cryptography", cryptography_module)
sys.modules.setdefault("cryptography.x509", cryptography_module.x509)
sys.modules.setdefault("cryptography.exceptions", cryptography_exceptions_module)
sys.modules.setdefault("cryptography.hazmat", hazmat_module)
sys.modules.setdefault("cryptography.hazmat.primitives", primitives_module)
sys.modules.setdefault("cryptography.hazmat.primitives.hashes", hashes_module)
sys.modules.setdefault("cryptography.hazmat.primitives.serialization", serialization_module)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric", asymmetric_module)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.padding", padding_module)
sys.modules.setdefault("cryptography.hazmat.backends", backends_module)

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
from token_factory._oauth_client_resolution import OAuthClientInfo


PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEI00000000000000000000000000000000000000000
-----END PRIVATE KEY-----"""


class FakeResponse:
    ok = True
    status_code = 200
    text = '{"access_token":"app-token","token_type":"Bearer","expires_in":3600}'

    def json(self):
        return {"access_token": "app-token", "token_type": "Bearer", "expires_in": 3600}


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


class TokenFactoryClientCredentialsChecks(unittest.TestCase):
    def test_oauth_with_none_credential_uses_client_credentials_grant(self):
        session = FakeSession()
        token_factory = TokenFactory(
            runtime_config={
                "domain_url": "https://idcs.example.com",
                "domain_region": "us-ashburn-1",
                "authz_policy_enable": False,
            },
            oauth_apps={
                "mcp-server": OAuthClientInfo(
                    client_credentials="client-id:client-secret",
                    issuer="https://issuer.example.com/",
                    private_key_pem=PRIVATE_KEY,
                )
            },
            token_endpoint_session=session,
        )

        result = token_factory.get_token(
            None,
            token_type="oauth",
            scope="database-scope",
            client_key="mcp-server",
        )

        self.assertEqual(result["access_token"], "app-token")
        self.assertEqual(result["issued_token_type"], "oauth")
        self.assertEqual(len(session.calls), 1)
        _url, request = session.calls[0]
        self.assertEqual(request["data"]["grant_type"], "client_credentials")
        self.assertEqual(request["data"]["scope"], "database-scope")
        self.assertNotIn("assertion", request["data"])
        self.assertEqual(
            base64.b64decode(request["headers"]["Authorization"].split(" ", 1)[1]).decode("utf-8"),
            "client-id:client-secret",
        )


if __name__ == "__main__":
    unittest.main()
