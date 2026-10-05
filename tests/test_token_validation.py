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


def hosting_component(allowed_client_ids=None):
    return types.SimpleNamespace(
        oauth_identity=types.SimpleNamespace(client_id="client-id", client_secret="client-secret"),
        resource_audiences=[],
        required_incoming_scopes=[],
        allowed_client_ids=allowed_client_ids,
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

    def test_client_check_is_off_when_no_allow_list_is_configured(self):
        result = MODULE._validated_from_claims({"sub": "user"}, hosting_component())

        self.assertEqual(result.claims["sub"], "user")

    def test_listed_client_and_hosting_app_itself_are_allowed(self):
        component = hosting_component(["agent-client-id"])

        for client_id in ("agent-client-id", "client-id"):
            with self.subTest(client_id=client_id):
                self.assertEqual(MODULE._validated_from_claims({"client_id": client_id}, component).claims["client_id"], client_id)

    def test_empty_allow_list_allows_only_the_hosting_app_itself(self):
        component = hosting_component([])

        MODULE._validated_from_claims({"client_id": "client-id"}, component)
        with self.assertRaisesRegex(MODULE.CallerAssertionValidationError, "'agent-client-id' is not an allowed client"):
            MODULE._validated_from_claims({"client_id": "agent-client-id"}, component)

    def test_unlisted_client_is_rejected(self):
        with self.assertRaisesRegex(MODULE.CallerAssertionValidationError, "'other-client-id' is not an allowed client"):
            MODULE._validated_from_claims({"client_id": "other-client-id"}, hosting_component(["agent-client-id"]))

    def test_missing_client_id_fails_closed_when_clients_are_restricted(self):
        for claims in ({}, {"client_id": ""}, {"client_id": None}):
            with self.subTest(claims=claims), self.assertRaisesRegex(MODULE.CallerAssertionValidationError, "missing client_id"):
                MODULE._validated_from_claims(claims, hosting_component(["agent-client-id"]))

    def test_introspection_client_id_drives_the_client_check(self):
        session = RecordingSession()
        session.post = lambda url, **kwargs: types.SimpleNamespace(ok=True, json=lambda: {"active": True, "client_id": "other-client-id"})
        validator = MODULE.TokenValidator(introspection_endpoint="https://oauth.example.net/introspect", session=session)

        with self.assertRaisesRegex(MODULE.CallerAssertionValidationError, "not an allowed client"):
            validator.validate("caller-token", hosting_component(["agent-client-id"]))

    def test_validation_module_contains_no_hardcoded_introspection_path(self):
        source = (ROOT / "_token_validation.py").read_text(encoding="utf-8")

        self.assertNotIn("/oauth2/v1/introspect", source)


if __name__ == "__main__":
    unittest.main()
