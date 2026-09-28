from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import patch


class _FakeJwt(types.ModuleType):
    def decode(self, *_args, **_kwargs):
        return {"exp": int(time.time()) + 1800}

    def encode(self, *_args, **_kwargs):
        return "signed.assertion"


def discovery_metadata(*, token_endpoint="https://oauth.example.net/custom/token", introspection_endpoint="https://oauth.example.net/custom/introspection"):
    return {
        "issuer": "https://identity.oraclecloud.com/",
        "jwks_uri": "https://idcs.example.com/admin/v1/SigningCert/jwk",
        "token_endpoint": token_endpoint,
        "introspection_endpoint": introspection_endpoint,
    }


class _FakeDiscoveryResponse:
    ok = True
    status_code = 200
    text = "{}"

    def __init__(self, payload=None):
        self.payload = payload or discovery_metadata()

    def json(self):
        return dict(self.payload)


class _FakePublicKey:
    def public_bytes(self, *_args, **_kwargs):
        return b"-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n"

    def verify(self, *_args, **_kwargs):
        return None


class _FakePrivateKey:
    def public_key(self):
        return _FakePublicKey()

    def private_bytes(self, *_args, **_kwargs):
        return b"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n"


class _FakeTokenExchangeSigner:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def _install_dependency_fakes() -> None:
    sys.modules["jwt"] = _FakeJwt("jwt")

    requests_module = types.ModuleType("requests")
    requests_module.get = lambda *_args, **_kwargs: _FakeDiscoveryResponse()
    sys.modules["requests"] = requests_module

    sys.modules["oci"] = types.ModuleType("oci")
    sys.modules["oci.auth"] = types.ModuleType("oci.auth")
    signers_module = types.ModuleType("oci.auth.signers")
    signers_module.TokenExchangeSigner = _FakeTokenExchangeSigner
    signers_module.InstancePrincipalsSecurityTokenSigner = lambda: "instance-principal-signer"
    signers_module.get_resource_principals_signer = lambda: "resource-principal-signer"
    signers_module.get_oke_workload_identity_resource_principal_signer = lambda: "oke-workload-identity-signer"
    sys.modules["oci.auth.signers"] = signers_module

    oci_config_module = types.ModuleType("oci.config")
    oci_config_module.from_file = lambda *_args, **_kwargs: {
        "tenancy": "tenancy",
        "user": "user",
        "fingerprint": "fingerprint",
        "region": "us-ashburn-1",
        "key_content": "private-key",
    }
    sys.modules["oci.config"] = oci_config_module

    key_management_module = types.ModuleType("oci.key_management")
    key_management_module.KmsCryptoClient = lambda *_args, **_kwargs: types.SimpleNamespace(sign=lambda _details: types.SimpleNamespace(data=types.SimpleNamespace(signature=base64.b64encode(b"kms-signature").decode("ascii"))))
    key_management_models_module = types.ModuleType("oci.key_management.models")
    key_management_models_module.SignDataDetails = lambda **kwargs: types.SimpleNamespace(**kwargs)
    sys.modules["oci.key_management"] = key_management_module
    sys.modules["oci.key_management.models"] = key_management_models_module

    identity_data_plane_module = types.ModuleType("oci.identity_data_plane")
    identity_data_plane_module.DataplaneClient = object
    sys.modules["oci.identity_data_plane"] = identity_data_plane_module
    identity_data_plane_models_module = types.ModuleType("oci.identity_data_plane.models")
    identity_data_plane_models_module.GenerateScopedAccessTokenDetails = object
    sys.modules["oci.identity_data_plane.models"] = identity_data_plane_models_module
    secrets_module = types.ModuleType("oci.secrets")
    secrets_module.SecretsClient = object
    sys.modules["oci.secrets"] = secrets_module
    signer_module = types.ModuleType("oci.signer")
    signer_module.Signer = object
    sys.modules["oci.signer"] = signer_module


def _import_package():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "token_factory",
        root / "__init__.py",
        submodule_search_locations=[str(root)],
    )
    package = importlib.util.module_from_spec(spec)
    sys.modules["token_factory"] = package
    assert spec.loader is not None
    spec.loader.exec_module(package)
    return package


_install_dependency_fakes()
token_factory = _import_package()

from token_factory import (  # noqa: E402
    AuthorizationError,
    AuthorizationPolicy,
    ConfigurationError,
    OAuthClientInfo,
    StaticAuthorizationPolicyProvider,
    TokenExchangeError,
    TokenFactory,
    TokenFactoryRuntimeConfig,
)
from token_factory._errors import CallerAssertionValidationError  # noqa: E402
from token_factory._factory_support import KmsJwtSigner  # noqa: E402
from token_factory._token_validation import ValidatedCallerAssertion  # noqa: E402


PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
test
-----END PRIVATE KEY-----"""


class FakeResponse:
    def __init__(self, payload=None, *, ok=True, status_code=200, text="{}"):
        self._payload = payload or {"access_token": "issued-token", "token_type": "Bearer", "expires_in": 3600}
        self.ok = ok
        self.status_code = status_code
        self.text = text

    def json(self):
        return dict(self._payload)


class FakeTokenEndpointSession:
    def __init__(self, response=None):
        self.calls = []
        self.response = response or FakeResponse()

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class DiscoveryFailingSession:
    def get(self, *_args, **_kwargs):
        raise AssertionError("OIDC discovery should not run")


class RecordingDiscoverySession:
    def __init__(self, payloads=None, error=None):
        self.payloads = list(payloads or [discovery_metadata()])
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        index = min(len(self.calls) - 1, len(self.payloads) - 1)
        return _FakeDiscoveryResponse(self.payloads[index])


class FakeTokenValidator:
    def __init__(self, *, claims=None, incoming_scopes=None, audience=None):
        self.calls = []
        self.claims = claims or {"sub": "user@example.com", "groups": ["users"]}
        self.incoming_scopes = incoming_scopes or []
        self.audience = audience or []

    def validate(self, token, hosting_component):
        self.calls.append((token, hosting_component.client_key))
        return ValidatedCallerAssertion(
            issuer=self.claims.get("iss"),
            audience=list(self.audience),
            incoming_scopes=list(self.incoming_scopes),
            claims=dict(self.claims),
        )


class RecordingJwtSigner:
    def __init__(self):
        self.signing_inputs = []

    def sign(self, signing_input):
        self.signing_inputs.append(signing_input)
        return b"kms-signature"


def oauth_apps(**overrides):
    info = {
        "client_credentials": "client-id:client-secret",
        "issuer": "https://issuer.example.com/",
        "kms_key_id": "ocid1.key.oc1..signing-key",
        "kms_key_version_id": "ocid1.keyversion.oc1..signing-key-version",
        "kms_crypto_endpoint": "https://kms.example.com",
        "kid": "orders-kid",
        "resource_audiences": ["https://orders.example.com/"],
    }
    info.update(overrides)
    return {"orders": OAuthClientInfo(**info)}


def runtime_config(**overrides):
    config = {
        "domain_url": "https://idcs-example.identity.oraclecloud.com",
        "domain_region": "us-ashburn-1",
        "authz_policy_enable": False,
    }
    config.update(overrides)
    return config


class TokenFactorySimplificationTests(unittest.TestCase):
    def test_constructor_discovers_identity_domain_metadata_once(self):
        discovery_session = RecordingDiscoverySession()

        factory = TokenFactory(runtime_config=runtime_config(timeout_seconds=17), oauth_apps=oauth_apps(), token_validation_session=discovery_session)

        self.assertEqual(discovery_session.calls, [("https://idcs-example.identity.oraclecloud.com/.well-known/openid-configuration", {"timeout": 17})])
        self.assertEqual(factory._identity_domain_metadata.token_endpoint, "https://oauth.example.net/custom/token")

    def test_custom_token_validator_still_discovers_once(self):
        discovery_session = RecordingDiscoverySession()

        TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(), token_validation_session=discovery_session, token_validator=FakeTokenValidator())

        self.assertEqual(len(discovery_session.calls), 1)

    def test_factory_reuses_immutable_discovery_snapshot(self):
        discovery_session = RecordingDiscoverySession([
            discovery_metadata(token_endpoint="https://oauth.example.net/first/token"),
            discovery_metadata(token_endpoint="https://oauth.example.net/second/token"),
        ])
        token_session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(issuer=None), token_endpoint_session=token_session, token_validation_session=discovery_session, token_validator=FakeTokenValidator(), oci_signer_builder=lambda _credential: "oci-signer")
        credential = {"tenancy": "tenancy", "user": "user", "fingerprint": "fingerprint", "region": "us-ashburn-1", "private_key_content": "key"}

        factory.get_token(None, "oauth", "orders.read", client_key="orders")
        factory.get_token_with_oci_credential(credential, scope="orders.read")

        self.assertEqual(len(discovery_session.calls), 1)
        self.assertEqual([call[0] for call in token_session.calls], ["https://oauth.example.net/first/token", "https://oauth.example.net/first/token"])

    def test_constructor_propagates_discovery_configuration_error(self):
        discovery_session = RecordingDiscoverySession(error=RuntimeError("unreachable"))

        with self.assertRaisesRegex(ConfigurationError, "OIDC discovery request failed"):
            TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(), token_validation_session=discovery_session)

    def test_kms_jwt_signer_sends_sha256_digest_for_long_signing_input(self):
        captured_details = []

        class CapturingKmsClient:
            def sign(self, details):
                captured_details.append(details)
                return types.SimpleNamespace(data=types.SimpleNamespace(signature=base64.b64encode(b"kms-signature").decode("ascii")))

        key_management_module = sys.modules["oci.key_management"]
        signing_input = b"x" * 520
        runtime = types.SimpleNamespace(oci_region="us-chicago-1")
        signer = KmsJwtSigner("key-id", "version-id", "https://crypto.example", lambda _runtime: "oci-signer", runtime)

        with patch.object(key_management_module, "KmsCryptoClient", lambda *_args, **_kwargs: CapturingKmsClient()):
            signature = signer.sign(signing_input)

        self.assertEqual(signature, b"kms-signature")
        self.assertEqual(captured_details[0].message_type, "DIGEST")
        self.assertEqual(base64.b64decode(captured_details[0].message), hashlib.sha256(signing_input).digest())

    def test_oauth_client_credentials_discovers_but_skips_private_key_resolution(self):
        session = FakeTokenEndpointSession()
        discovery_session = RecordingDiscoverySession()
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps( issuer=None),
            token_endpoint_session=session,
            token_validation_session=discovery_session,
        )

        result = factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(result["access_token"], "issued-token")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(session.calls[0][1]["data"]["grant_type"], "client_credentials")
        self.assertEqual(session.calls[0][1]["data"]["scope"], "database-scope")
        self.assertNotIn("assertion", session.calls[0][1]["data"])
        self.assertEqual(len(discovery_session.calls), 1)

    def test_client_credentials_uses_discovered_token_endpoint(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(issuer=None), token_endpoint_session=session, token_validation_session=RecordingDiscoverySession())

        factory.get_token(None, "oauth", "orders.read", client_key="orders")

        self.assertEqual(session.calls[0][0], "https://oauth.example.net/custom/token")

    def test_jwt_bearer_uses_discovered_token_endpoint(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(), token_endpoint_session=session, token_validation_session=RecordingDiscoverySession(), token_validator=FakeTokenValidator(incoming_scopes=["other"]))

        factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        self.assertEqual(session.calls[0][0], "https://oauth.example.net/custom/token")

    def test_oci_credential_uses_discovered_token_endpoint(self):
        session = FakeTokenEndpointSession()
        credential = {"tenancy": "tenancy", "user": "user", "fingerprint": "fingerprint", "region": "us-ashburn-1", "private_key_content": "key"}
        factory = TokenFactory(runtime_config=runtime_config(), token_endpoint_session=session, token_validation_session=RecordingDiscoverySession(), oci_signer_builder=lambda _credential: "oci-signer")

        factory.get_token_with_oci_credential(credential, scope="orders.read")

        self.assertEqual(session.calls[0][0], "https://oauth.example.net/custom/token")

    def test_identity_propagation_uses_discovered_token_endpoint(self):
        kms_signer = RecordingJwtSigner()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(), token_validation_session=RecordingDiscoverySession(), token_validator=FakeTokenValidator(), token_exchange_signer_cls=_FakeTokenExchangeSigner, jwt_assertion_signer=kms_signer)

        exchange_signer = factory.get_token("caller.jwt", "oci-service", client_key="orders")

        assertion = exchange_signer.args[0]
        payload_segment = assertion.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))
        self.assertEqual(payload["aud"], "https://oauth.example.net/custom/token")

    def test_app_assertion_issuer_remains_explicit(self):
        session = FakeTokenEndpointSession()
        kms_signer = RecordingJwtSigner()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps(issuer="https://app.example.com/assertions"), token_endpoint_session=session, token_validation_session=RecordingDiscoverySession(), token_validator=FakeTokenValidator(incoming_scopes=["other"]), jwt_assertion_signer=kms_signer)

        factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        assertion = session.calls[0][1]["data"]["assertion"]
        payload_segment = assertion.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))
        self.assertEqual(payload["iss"], "https://app.example.com/assertions")
        self.assertNotEqual(payload["iss"], "https://identity.oraclecloud.com/")

    def test_factory_module_contains_no_hardcoded_token_or_introspection_path(self):
        source = (Path(__file__).resolve().parents[1] / "factory.py").read_text(encoding="utf-8")

        self.assertNotIn("/oauth2/v1/token", source)
        self.assertNotIn("/oauth2/v1/introspect", source)

    def test_oci_principal_database_token_skips_caller_validation(self):
        calls = []
        validator = FakeTokenValidator()

        def db_token_generator(signer, public_key_pem, scope, config):
            calls.append((signer, public_key_pem, scope, config.oci_auth_mode))
            return "header.payload.signature"

        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_validator=validator,
            factory_oci_signer_builder=lambda _config: "factory-signer",
            db_token_generator=db_token_generator,
        )

        result = factory.get_token("oracle-database", "oci_principal", "urn:oracle:db::id::*", client_key="orders")

        self.assertEqual(validator.calls, [])
        self.assertEqual(result.principal_mode, "oci_principal")
        self.assertEqual(calls[0][0], "factory-signer")
        self.assertIn("BEGIN PUBLIC KEY", calls[0][1])

    def test_assertion_backed_oauth_exchanges_jwt_bearer_assertion(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_endpoint_session=session,
            token_validator=FakeTokenValidator(incoming_scopes=["other"]),
        )

        result = factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        self.assertEqual(result["access_token"], "issued-token")
        request = session.calls[0][1]
        self.assertEqual(request["data"]["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer")
        self.assertEqual(request["data"]["assertion"].count("."), 2)

    def test_assertion_backed_oauth_uses_injected_kms_jwt_signer(self):
        session = FakeTokenEndpointSession()
        kms_signer = RecordingJwtSigner()
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_endpoint_session=session,
            token_validator=FakeTokenValidator(incoming_scopes=["other"]),
            jwt_assertion_signer=kms_signer,
        )

        factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        assertion = session.calls[0][1]["data"]["assertion"]
        header, payload, signature = assertion.split(".")
        self.assertEqual(kms_signer.signing_inputs, [f"{header}.{payload}".encode("ascii")])
        self.assertEqual(json.loads(base64.urlsafe_b64decode(header + "==")), {"alg": "RS256", "kid": "orders-kid", "typ": "JWT"})
        self.assertEqual(signature, base64.urlsafe_b64encode(b"kms-signature").rstrip(b"=").decode("ascii"))

    def test_userid_returns_validated_subject(self):
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_validator=FakeTokenValidator(claims={"sub": "alice@example.com", "groups": []}),
        )

        result = factory.get_token("caller.jwt", "userid", client_key="orders")

        self.assertEqual(result, {"issued_token_type": "userid", "user_id": "alice@example.com"})

    def test_oci_service_returns_upst_signer(self):
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_validator=FakeTokenValidator(),
        )

        signer = factory.get_token("caller.jwt", "oci-service", client_key="orders")

        self.assertIsInstance(signer, _FakeTokenExchangeSigner)
        self.assertEqual(signer.args[0].count("."), 2)
        self.assertEqual(signer.kwargs["region"], "us-ashburn-1")

    def test_assertion_backed_oracle_database_returns_tuple_shape(self):
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_validator=FakeTokenValidator(),
            token_exchange_signer_cls=lambda *_args, **_kwargs: "upst-signer",
            signer_keypair_extractor=lambda _signer: ("public-key", "private-key"),
            db_token_generator=lambda *_args: "header.payload.signature",
        )

        result = factory.get_token("caller.jwt", "oracle-database", "urn:oracle:db::id::*", client_key="orders")

        self.assertEqual(tuple(result)[:2], ("header.payload.signature", "private-key"))
        self.assertEqual(result.principal_mode, "user")
        self.assertEqual(result.issued_token_type, "oracle-database")

    def test_oauth_passes_through_valid_incoming_token(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(
            runtime_config=runtime_config(),
            oauth_apps=oauth_apps(),
            token_endpoint_session=session,
            token_validator=FakeTokenValidator(
                incoming_scopes=["orders.read"],
                audience=["https://orders.example.com/"],
            ),
        )

        result = factory.get_token("caller.jwt", "oauth", "https://orders.example.com/orders.read", client_key="orders")

        self.assertEqual(result["access_token"], "caller.jwt")
        self.assertEqual(result["source"], "incoming_token")
        self.assertEqual(session.calls, [])

    def test_authorization_enabled_denies_missing_group_scope(self):
        policy = AuthorizationPolicy(version=1, grants={"oauth": {"admins": ["orders.read"]}})
        factory = TokenFactory(
            runtime_config=runtime_config(authz_policy_enable=True),
            oauth_apps=oauth_apps(),
            authorization_policy_provider=StaticAuthorizationPolicyProvider(policy),
            token_validator=FakeTokenValidator(claims={"sub": "user@example.com", "groups": ["users"]}),
        )

        with self.assertRaises(AuthorizationError):
            factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

    def test_authorization_disabled_skips_policy(self):
        policy = AuthorizationPolicy(version=1, grants={"oauth": {"admins": ["orders.read"]}})
        session = FakeTokenEndpointSession()
        factory = TokenFactory(
            runtime_config=runtime_config(authz_policy_enable=False),
            oauth_apps=oauth_apps(),
            authorization_policy_provider=StaticAuthorizationPolicyProvider(policy),
            token_endpoint_session=session,
            token_validator=FakeTokenValidator(claims={"sub": "user@example.com", "groups": ["users"]}),
        )

        result = factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        self.assertEqual(result["access_token"], "issued-token")

    def test_process_selector_is_reserved(self):
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps())

        with self.assertRaises(NotImplementedError):
            factory.get_token("oracle-database", "PROCESS", "urn:oracle:db::id::*", client_key="orders")

    def test_oci_principal_accepts_oci_profile_mode(self):
        calls = []
        factory = TokenFactory(
            runtime_config=runtime_config(oci_auth_mode="oci-profile"),
            oauth_apps=oauth_apps(),
            factory_oci_signer_builder=lambda _config: "factory-signer",
            db_token_generator=lambda signer, public_key, scope, _config: calls.append((signer, public_key, scope)) or "header.payload.signature",
        )

        result = factory.get_token("oracle-database", "OCI_PRINCIPAL", "urn:oracle:db::id::*", client_key="orders")

        self.assertEqual(result.principal_mode, "oci_principal")
        self.assertEqual(calls[0][0], "factory-signer")

    def test_oke_workload_identity_uses_oke_signer(self):
        factory_support = sys.modules["token_factory._factory_support"]
        config = type("Config", (), {"oci_auth_mode": "oke-workload-identity", "oci_auth_profile": "DEFAULT"})()

        self.assertEqual(factory_support._get_factory_oci_signer(config), "oke-workload-identity-signer")

    def test_get_token_with_oci_credential_uses_signer_dictionary(self):
        session = FakeTokenEndpointSession()
        signer_calls = []
        factory = TokenFactory(
            runtime_config=runtime_config(),
            token_endpoint_session=session,
            oci_signer_builder=lambda credential: signer_calls.append(credential) or "oci-signer",
        )
        credential = {
            "tenancy": "tenancy",
            "user": "user",
            "fingerprint": "fingerprint",
            "region": "us-ashburn-1",
            "private_key_content": "key",
        }

        result = factory.get_token_with_oci_credential(credential, scope="orders.read")

        self.assertEqual(result["access_token"], "issued-token")
        self.assertEqual(signer_calls, [credential])
        self.assertEqual(session.calls[0][1]["auth"], "oci-signer")

    def test_get_token_with_oci_credential_resolves_profile_name(self):
        factory_module = sys.modules["token_factory.factory"]
        original = factory_module.build_signer_credential_from_profile
        session = FakeTokenEndpointSession()
        signer_calls = []
        try:
            factory_module.build_signer_credential_from_profile = lambda profile: {
                "profile": profile,
                "tenancy": "tenancy",
                "user": "user",
                "fingerprint": "fingerprint",
                "region": "us-ashburn-1",
                "private_key_content": "key",
            }
            factory = TokenFactory(
                runtime_config=runtime_config(),
                token_endpoint_session=session,
                oci_signer_builder=lambda credential: signer_calls.append(credential) or "profile-signer",
            )

            result = factory.get_token_with_oci_credential("DEFAULT")
        finally:
            factory_module.build_signer_credential_from_profile = original

        self.assertEqual(result["access_token"], "issued-token")
        self.assertEqual(signer_calls[0]["profile"], "DEFAULT")
        self.assertEqual(session.calls[0][1]["auth"], "profile-signer")

    def test_cache_enable_defaults_false_and_reads_env(self):
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1"}, clear=True):
            self.assertFalse(TokenFactoryRuntimeConfig.from_env().cache_enable)
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1", "TF_SHARED_CACHE_ENABLE": "true"}, clear=True):
            self.assertTrue(TokenFactoryRuntimeConfig.from_env().cache_enable)

    def test_cache_max_size_defaults_and_reads_env(self):
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1"}, clear=True):
            self.assertEqual(TokenFactoryRuntimeConfig.from_env().cache_max_size, 1024)
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1", "TF_SHARED_CACHE_MAX_SIZE": ""}, clear=True):
            self.assertEqual(TokenFactoryRuntimeConfig.from_env().cache_max_size, 1024)
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1", "TF_SHARED_CACHE_MAX_SIZE": "2"}, clear=True):
            self.assertEqual(TokenFactoryRuntimeConfig.from_env().cache_max_size, 2)

    def test_cache_max_size_rejects_invalid_values(self):
        with patch.dict(os.environ, {"TF_SHARED_DOMAIN_URL": "https://idcs.example.com", "TF_SHARED_DOMAIN_REGION": "us-ashburn-1", "TF_SHARED_CACHE_MAX_SIZE": "nope"}, clear=True):
            with self.assertRaises(ValueError):
                TokenFactoryRuntimeConfig.from_env()
        with self.assertRaises(ValueError):
            TokenFactoryRuntimeConfig(domain_url="https://idcs.example.com", domain_region="us-ashburn-1", cache_max_size=0)

    def test_cache_disabled_by_default_does_not_reuse_client_credentials_token(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        factory.get_token(None, "oauth", "database-scope", client_key="orders")
        factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(len(session.calls), 2)

    def test_constructor_override_can_enable_client_credentials_cache(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=False), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session, token_cache_enabled=True)

        first = factory.get_token(None, "oauth", "database-scope", client_key="orders")
        second = factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(first["access_token"], "issued-token")
        self.assertEqual(second["access_token"], "issued-token")
        self.assertEqual(len(session.calls), 1)

    def test_constructor_override_can_disable_runtime_cache(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session, token_cache_enabled=False)

        factory.get_token(None, "oauth", "database-scope", client_key="orders")
        factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(len(session.calls), 2)

    def test_assertion_backed_oauth_cache_still_validates_every_call(self):
        session = FakeTokenEndpointSession()
        validator = FakeTokenValidator(incoming_scopes=["other"])
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps(), token_endpoint_session=session, token_validator=validator)

        first = factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")
        second = factory.get_token("caller.jwt", "oauth", "orders.read", client_key="orders")

        self.assertEqual(first["access_token"], "issued-token")
        self.assertEqual(second["access_token"], "issued-token")
        self.assertEqual(len(validator.calls), 2)
        self.assertEqual(len(session.calls), 1)

    def test_expired_oauth_cache_entry_triggers_new_exchange(self):
        session = FakeTokenEndpointSession(FakeResponse({"access_token": "issued-token", "token_type": "Bearer", "expires_in": 1}))
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        factory.get_token(None, "oauth", "database-scope", client_key="orders")
        factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(len(session.calls), 2)

    def test_cache_key_separates_scope(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        factory.get_token(None, "oauth", "database-scope-a", client_key="orders")
        factory.get_token(None, "oauth", "database-scope-b", client_key="orders")

        self.assertEqual(len(session.calls), 2)

    def test_cached_dict_mutation_does_not_poison_cache(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        first = factory.get_token(None, "oauth", "database-scope", client_key="orders")
        first["access_token"] = "mutated"
        second = factory.get_token(None, "oauth", "database-scope", client_key="orders")

        self.assertEqual(second["access_token"], "issued-token")
        self.assertEqual(len(session.calls), 1)

    def test_cache_logs_miss_and_hit(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        with self.assertLogs("token_factory", level="INFO") as logs:
            factory.get_token(None, "oauth", "database-scope", client_key="orders")
            factory.get_token(None, "oauth", "database-scope", client_key="orders")

        rendered_logs = "\n".join(logs.output)
        self.assertIn("TokenFactory cache miss label=oauth-client-credentials reason=absent", rendered_logs)
        self.assertIn("TokenFactory cache hit label=oauth-client-credentials", rendered_logs)

    def test_cache_evicts_least_recently_used_entry_when_max_size_is_reached(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True, cache_max_size=2), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        factory.get_token(None, "oauth", "scope-a", client_key="orders")
        factory.get_token(None, "oauth", "scope-b", client_key="orders")
        factory.get_token(None, "oauth", "scope-a", client_key="orders")
        factory.get_token(None, "oauth", "scope-c", client_key="orders")
        factory.get_token(None, "oauth", "scope-b", client_key="orders")

        self.assertEqual(len(session.calls), 4)

    def test_cache_eviction_is_logged(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True, cache_max_size=1), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session)

        with self.assertLogs("token_factory", level="INFO") as logs:
            factory.get_token(None, "oauth", "scope-a", client_key="orders")
            factory.get_token(None, "oauth", "scope-b", client_key="orders")

        self.assertIn("TokenFactory cache eviction reason=max_size", "\n".join(logs.output))

    def test_constructor_override_can_set_cache_max_size(self):
        session = FakeTokenEndpointSession()
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True, cache_max_size=10), oauth_apps=oauth_apps( issuer=None), token_endpoint_session=session, token_cache_max_size=1)

        factory.get_token(None, "oauth", "scope-a", client_key="orders")
        factory.get_token(None, "oauth", "scope-b", client_key="orders")
        factory.get_token(None, "oauth", "scope-a", client_key="orders")

        self.assertEqual(len(session.calls), 3)

    def test_oci_principal_database_token_cache_reuses_generator_result(self):
        calls = []

        def db_token_generator(signer, public_key_pem, scope, config):
            calls.append((signer, public_key_pem, scope, config.oci_auth_mode))
            return "header.payload.signature"

        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps(), factory_oci_signer_builder=lambda _config: "factory-signer", db_token_generator=db_token_generator)

        first = factory.get_token("oracle-database", "oci_principal", "urn:oracle:db::id::*", client_key="orders")
        second = factory.get_token("oracle-database", "oci_principal", "urn:oracle:db::id::*", client_key="orders")

        self.assertIs(first, second)
        self.assertEqual(len(calls), 1)

    def test_assertion_backed_database_cache_still_validates_every_call(self):
        calls = []
        validator = FakeTokenValidator()

        def db_token_generator(signer, public_key_pem, scope, config):
            calls.append((signer, public_key_pem, scope))
            return "header.payload.signature"

        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps(), token_validator=validator, token_exchange_signer_cls=lambda *_args, **_kwargs: "upst-signer", signer_keypair_extractor=lambda _signer: ("public-key", "private-key"), db_token_generator=db_token_generator)

        first = factory.get_token("caller.jwt", "oracle-database", "urn:oracle:db::id::*", client_key="orders")
        second = factory.get_token("caller.jwt", "oracle-database", "urn:oracle:db::id::*", client_key="orders")

        self.assertIs(first, second)
        self.assertEqual(len(validator.calls), 2)
        self.assertEqual(len(calls), 1)

    def test_oci_service_cache_still_validates_every_call(self):
        validator = FakeTokenValidator()
        signer_calls = []

        class CountingTokenExchangeSigner(_FakeTokenExchangeSigner):
            def __init__(self, *args, **kwargs):
                signer_calls.append((args, kwargs))
                super().__init__(*args, **kwargs)

        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), oauth_apps=oauth_apps(), token_validator=validator, token_exchange_signer_cls=CountingTokenExchangeSigner)

        first = factory.get_token("caller.jwt", "oci-service", client_key="orders")
        second = factory.get_token("caller.jwt", "oci-service", client_key="orders")

        self.assertIs(first, second)
        self.assertEqual(len(validator.calls), 2)
        self.assertEqual(len(signer_calls), 1)

    def test_get_token_with_oci_credential_cache_reuses_oauth_exchange(self):
        session = FakeTokenEndpointSession()
        signer_calls = []
        credential = {"tenancy": "tenancy", "user": "user", "fingerprint": "fingerprint", "region": "us-ashburn-1", "private_key_content": "key"}
        factory = TokenFactory(runtime_config=runtime_config(cache_enable=True), token_endpoint_session=session, oci_signer_builder=lambda value: signer_calls.append(value) or "oci-signer")

        first = factory.get_token_with_oci_credential(credential, scope="orders.read")
        second = factory.get_token_with_oci_credential(credential, scope="orders.read")

        self.assertEqual(first["access_token"], "issued-token")
        self.assertEqual(second["access_token"], "issued-token")
        self.assertEqual(len(signer_calls), 1)
        self.assertEqual(len(session.calls), 1)


class HttpServiceTests(unittest.TestCase):
    def setUp(self):
        self.http_service = importlib.import_module("token_factory.http_service")
        self.original_exchange_token = self.http_service.exchange_token

    def tearDown(self):
        self.http_service.exchange_token = self.original_exchange_token

    def test_handle_request_returns_400_for_missing_token(self):
        status, _headers, body = self.http_service.handle_request({"token_type": "oauth", "client_key": "orders", "scope": "orders.read"})

        self.assertEqual(status, 400)
        self.assertIn("access_token", body["message"])

    def test_handle_request_returns_200_for_success(self):
        self.http_service.exchange_token = lambda *_args, **_kwargs: {"token": "issued-token"}

        status, _headers, body = self.http_service.handle_request(
            {"token_type": "oauth", "client_key": "orders", "scope": "orders.read", "access_token": "caller.jwt"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["token"], "issued-token")

    def test_handle_request_maps_expected_errors(self):
        cases = [
            (CallerAssertionValidationError("bad assertion"), 401),
            (AuthorizationError("denied"), 403),
            (TokenExchangeError("upstream failed"), 502),
        ]
        for error, expected_status in cases:
            with self.subTest(error=type(error).__name__):
                self.http_service.exchange_token = lambda *_args, error=error, **_kwargs: (_ for _ in ()).throw(error)
                status, _headers, body = self.http_service.handle_request(
                    {"token_type": "oauth", "client_key": "orders", "scope": "orders.read", "access_token": "caller.jwt"}
                )
                self.assertEqual(status, expected_status)
                self.assertEqual(body["message"], str(error))


if __name__ == "__main__":
    unittest.main()
