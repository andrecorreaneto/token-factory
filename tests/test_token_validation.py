import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_PACKAGE = "token_factory_validation_test"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


package = types.ModuleType(TEST_PACKAGE)
package.__path__ = [str(ROOT)]
sys.modules[TEST_PACKAGE] = package
errors = types.ModuleType(f"{TEST_PACKAGE}._errors")
errors.CallerAssertionValidationError = type("CallerAssertionValidationError", (RuntimeError,), {})
sys.modules[errors.__name__] = errors
_load_module(f"{TEST_PACKAGE}._normalization", ROOT / "_normalization.py")
resolution = types.ModuleType(f"{TEST_PACKAGE}._oauth_client_resolution")
resolution.ResolvedHostingComponent = object
sys.modules[resolution.__name__] = resolution
MODULE = _load_module(f"{TEST_PACKAGE}._token_validation", ROOT / "_token_validation.py")


class IntrospectionResponse:
    ok = True
    status_code = 200
    text = "{}"

    def json(self):
        return {"active": True, "sub": "introspected-user"}


class RecordingSession:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return IntrospectionResponse()


def hosting_component():
    return types.SimpleNamespace(
        oauth_identity=types.SimpleNamespace(client_id="client-id", client_secret="client-secret"),
        resource_audiences=[],
        required_incoming_scopes=[],
    )


class TokenValidationTests(unittest.TestCase):
    def test_token_validator_posts_to_exact_injected_introspection_endpoint(self):
        session = RecordingSession()
        endpoint = "https://oauth.example.net/custom/introspection"
        validator = MODULE.TokenValidator(introspection_endpoint=endpoint, timeout_seconds=19, session=session)

        result = validator.validate("caller-token", hosting_component())

        self.assertEqual(result.subject if hasattr(result, "subject") else result.claims["sub"], "introspected-user")
        self.assertEqual(session.calls[0][0], endpoint)
        self.assertEqual(session.calls[0][1]["timeout"], 19)

    def test_hybrid_validator_passes_exact_endpoint_to_introspection_validator(self):
        session = RecordingSession()
        endpoint = "https://oauth.example.net/custom/introspection"
        validator = MODULE.HybridTokenValidator(introspection_endpoint=endpoint, trusted_issuers={"https://issuer.example": {"public_key_pem": "key"}}, jwt_claim_overrides=["sub"], timeout_seconds=23, session=session)
        validator._jwt_validator = types.SimpleNamespace(validate=lambda _token, _component: MODULE.ValidatedCallerAssertion(issuer="https://issuer.example", audience=[], incoming_scopes=[], claims={"sub": "signed-user"}))

        result = validator.validate("caller-token", hosting_component())

        self.assertEqual(result.claims["sub"], "signed-user")
        self.assertEqual(session.calls[0][0], endpoint)
        self.assertEqual(session.calls[0][1]["timeout"], 23)

    def test_validation_module_contains_no_hardcoded_introspection_path(self):
        source = (ROOT / "_token_validation.py").read_text(encoding="utf-8")

        self.assertNotIn("/oauth2/v1/introspect", source)


if __name__ == "__main__":
    unittest.main()
