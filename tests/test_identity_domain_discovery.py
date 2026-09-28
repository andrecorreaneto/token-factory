import importlib.util
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_PACKAGE = "token_factory_discovery_test"

package = types.ModuleType(TEST_PACKAGE)
package.__path__ = [str(ROOT)]
sys.modules[TEST_PACKAGE] = package
support = types.ModuleType(f"{TEST_PACKAGE}._factory_support")
support.ConfigurationError = type("ConfigurationError", (RuntimeError,), {})
sys.modules[support.__name__] = support
spec = importlib.util.spec_from_file_location(f"{TEST_PACKAGE}._identity_domain_discovery", ROOT / "_identity_domain_discovery.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)
discover_identity_domain_metadata = module.discover_identity_domain_metadata


class DiscoveryResponse:
    def __init__(self, payload, *, ok=True, status_code=200, text="", json_error=None):
        self.payload = payload
        self.ok = ok
        self.status_code = status_code
        self.text = text
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


class DiscoverySession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class FailingDiscoverySession:
    def get(self, _url, **_kwargs):
        raise RuntimeError("network-detail-must-not-leak")


def valid_metadata():
    return {
        "issuer": "https://identity.oraclecloud.com/",
        "jwks_uri": "https://idcs.example.com/admin/v1/SigningCert/jwk",
        "token_endpoint": "https://idcs.example.com/oauth2/v1/token",
        "introspection_endpoint": "https://idcs.example.com/oauth2/v1/introspect",
    }


class IdentityDomainDiscoveryTests(unittest.TestCase):
    def test_discovers_required_metadata_from_normalized_base_url(self):
        for domain_url in ("https://idcs.example.com", "https://idcs.example.com///"):
            with self.subTest(domain_url=domain_url):
                session = DiscoverySession(DiscoveryResponse(valid_metadata()))

                metadata = discover_identity_domain_metadata(domain_url, 17, session)

                self.assertEqual(session.calls, [("https://idcs.example.com/.well-known/openid-configuration", {"timeout": 17})])
                self.assertEqual(metadata.issuer, "https://identity.oraclecloud.com/")
                self.assertEqual(metadata.jwks_uri, "https://idcs.example.com/admin/v1/SigningCert/jwk")
                self.assertEqual(metadata.token_endpoint, "https://idcs.example.com/oauth2/v1/token")
                self.assertEqual(metadata.introspection_endpoint, "https://idcs.example.com/oauth2/v1/introspect")
                with self.assertRaises(FrozenInstanceError):
                    metadata.token_endpoint = "https://changed.example.com/token"

    def test_rejects_request_exception_without_response_content(self):
        with self.assertRaisesRegex(RuntimeError, "OIDC discovery request failed") as raised:
            discover_identity_domain_metadata("https://idcs.example.com", 17, FailingDiscoverySession())

        self.assertIn("https://idcs.example.com/.well-known/openid-configuration", str(raised.exception))
        self.assertNotIn("network-detail-must-not-leak", str(raised.exception))

    def test_rejects_unsuccessful_response_without_response_content(self):
        session = DiscoverySession(DiscoveryResponse({}, ok=False, status_code=503, text="response-body-must-not-leak"))

        with self.assertRaisesRegex(RuntimeError, "status 503") as raised:
            discover_identity_domain_metadata("https://idcs.example.com", 17, session)

        self.assertNotIn("response-body-must-not-leak", str(raised.exception))

    def test_rejects_invalid_json_without_parser_detail(self):
        session = DiscoverySession(DiscoveryResponse(None, json_error=ValueError("parser-detail-must-not-leak")))

        with self.assertRaisesRegex(RuntimeError, "invalid JSON") as raised:
            discover_identity_domain_metadata("https://idcs.example.com", 17, session)

        self.assertNotIn("parser-detail-must-not-leak", str(raised.exception))

    def test_rejects_non_object_json(self):
        for payload in ([], "metadata", 1, None):
            with self.subTest(payload=payload):
                session = DiscoverySession(DiscoveryResponse(payload))
                with self.assertRaisesRegex(RuntimeError, "must be a JSON object"):
                    discover_identity_domain_metadata("https://idcs.example.com", 17, session)

    def test_rejects_missing_or_empty_required_field(self):
        for field_name in ("issuer", "jwks_uri", "token_endpoint", "introspection_endpoint"):
            for value in (None, "", "   "):
                with self.subTest(field_name=field_name, value=value):
                    payload = valid_metadata()
                    if value is None:
                        payload.pop(field_name)
                    else:
                        payload[field_name] = value
                    session = DiscoverySession(DiscoveryResponse(payload))
                    with self.assertRaisesRegex(RuntimeError, field_name):
                        discover_identity_domain_metadata("https://idcs.example.com", 17, session)

    def test_rejects_non_https_or_relative_required_urls(self):
        for field_name in ("issuer", "jwks_uri", "token_endpoint", "introspection_endpoint"):
            for value in ("http://idcs.example.com/value", "/relative/value"):
                with self.subTest(field_name=field_name, value=value):
                    payload = valid_metadata()
                    payload[field_name] = value
                    session = DiscoverySession(DiscoveryResponse(payload))
                    with self.assertRaisesRegex(RuntimeError, field_name):
                        discover_identity_domain_metadata("https://idcs.example.com", 17, session)

    def test_rejects_unsafe_base_or_endpoint_urls(self):
        unsafe_urls = (
            "https://user:password@idcs.example.com",
            "https://idcs.example.com?query=value",
            "https://idcs.example.com#fragment",
        )
        for domain_url in unsafe_urls:
            with self.subTest(domain_url=domain_url):
                session = DiscoverySession(DiscoveryResponse(valid_metadata()))
                with self.assertRaisesRegex(RuntimeError, "identity_domain_url"):
                    discover_identity_domain_metadata(domain_url, 17, session)
                self.assertEqual(session.calls, [])

        for field_name in ("issuer", "jwks_uri", "token_endpoint", "introspection_endpoint"):
            for value in unsafe_urls:
                with self.subTest(field_name=field_name, value=value):
                    payload = valid_metadata()
                    payload[field_name] = value
                    session = DiscoverySession(DiscoveryResponse(payload))
                    with self.assertRaisesRegex(RuntimeError, field_name):
                        discover_identity_domain_metadata("https://idcs.example.com", 17, session)


if __name__ == "__main__":
    unittest.main()
