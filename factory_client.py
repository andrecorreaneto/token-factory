import argparse
import json
from typing import Any, Dict, List, Optional

from token_factory import TokenFactory
from token_factory._factory_support import build_signer_credential_from_profile

SUPPORTED_TARGET_TOOLS = ("oracle-database", "oci-service", "oauth", "userid")

CONFIG_OVERRIDES = {
    "TOKEN_FACTORY_LOG_LEVEL": "INFO",
    "TOKEN_FACTORY_DOMAIN_URL": "https://<identity-domain>.identity.oraclecloud.com:443",
    "TOKEN_FACTORY_TIMEOUT_SECONDS": "30",
    "TOKEN_FACTORY_CREDS_SECRET_OCID": "ocid1.vaultsecret.oc1..<token-factory-creds-secret>",
    # "TOKEN_FACTORY_CREDS": "client-id:client-secret",
    "TOKEN_FACTORY_OCI_REGION": "<vault-secret-region>",
    "TOKEN_FACTORY_OCI_AUTH_MODE": "oci-profile",
    "TOKEN_FACTORY_OCI_AUTH_PROFILE": "DEFAULT",
    "TOKEN_FACTORY_DOMAIN_REGION": "<identity-domain-region>",
    "TOKEN_FACTORY_ISSUER": "https://upst.tokenfactory/",
    "TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID": "ocid1.vaultsecret.oc1..<private-key-secret>",
    # "TOKEN_FACTORY_PRIVATE_KEY_PATH": "/path/to/jwt_assertion_private_key.pem",
    # "TOKEN_FACTORY_PRIVATE_KEY_PEM": "-----BEGIN PRIVATE KEY-----...",
    # "TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID": "ocid1.vaultsecret.oc1..<passphrase-secret>",
    # "TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE": "private-key-passphrase",
    "TOKEN_FACTORY_CERT_SECRET_OCID": "ocid1.vaultsecret.oc1..<certificate-secret>",
    # "TOKEN_FACTORY_CERT_PATH": "/path/to/jwt_assertion_certificate.pem",
    # "TOKEN_FACTORY_CERT_PEM": "-----BEGIN CERTIFICATE-----...",
    "TOKEN_FACTORY_KID": "token-factory-cert",
}

INCOMING_ACCESS_TOKEN = "<caller-access-token>"

MCP_SERVER_SCOPE = "<mcp-server-scope>"
MY_SCOPES = "urn:opc:idm:__myscopes__"
OCI_CLI_PROFILE_NAME = "DEFAULT"
TARGET_TOOL_SCOPES = {
    "oracle-database": "urn:oracle:db::id::*",
    "oauth": MY_SCOPES,
    "userid": MCP_SERVER_SCOPE,
}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Example client showing how to call the TokenFactory OO API for each supported flow."
    )
    parser.add_argument(
        "--target-tool",
        choices=SUPPORTED_TARGET_TOOLS,
        help="Run only one target_tool flow. Defaults to all flows when omitted.",
    )
    return parser.parse_args(argv)


def build_factory() -> TokenFactory:
    return TokenFactory(CONFIG_OVERRIDES)


def resolve_scope(target_tool: str) -> Optional[str]:
    return TARGET_TOOL_SCOPES.get(target_tool)


def resolve_credential(target_tool: str) -> Any:
    if target_tool in ("oracle-database", "oci-service"):
        return INCOMING_ACCESS_TOKEN
    if target_tool == "oauth":
        return build_signer_credential_from_profile(OCI_CLI_PROFILE_NAME)
    if target_tool == "userid":
        return INCOMING_ACCESS_TOKEN

    raise ValueError(f"Unsupported target_tool '{target_tool}'")


def run_profile_oauth_example(factory: TokenFactory) -> Any:
    return factory.get_token(
        resolve_credential("oauth"),
        "oauth",
        TARGET_TOOL_SCOPES["oauth"],
    )


def run_target_tool(factory: TokenFactory, target_tool: str) -> Any:
    return factory.get_token(
        resolve_credential(target_tool),
        target_tool,
        resolve_scope(target_tool),
    )


def _extract_oci_service_token(result: Any) -> str:
    get_security_token = getattr(result, "get_security_token", None)
    if callable(get_security_token):
        token = get_security_token()
        if token:
            return token

    security_token_container = getattr(result, "security_token_container", None)
    token = getattr(security_token_container, "security_token", None)
    if token:
        return token

    raise ValueError("OCI service signer did not expose a security token.")


def serialize_result(result: Any, target_tool: str) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result

    if target_tool == "oracle-database" and isinstance(result, tuple):
        payload: Dict[str, Any] = {
            "token": result[0],
            "private_key_pem": result[1],
        }
        if len(result) > 2:
            payload["expires_in"] = result[2]
        if len(result) > 3:
            payload["token_type"] = result[3]
        if len(result) > 4:
            payload["issued_token_type"] = result[4]
        return payload

    if target_tool == "oci-service":
        return {
            "issued_token_type": "oci-service",
            "signer_type": type(result).__name__,
            "token": _extract_oci_service_token(result),
        }

    return {"result_type": type(result).__name__, "value": str(result)}


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    targets = [args.target_tool] if args.target_tool else list(SUPPORTED_TARGET_TOOLS)

    factory = build_factory()
    results: Dict[str, Dict[str, Any]] = {}
    exit_code = 0

    for target_tool in targets:
        try:
            results[target_tool] = serialize_result(
                run_target_tool(factory, target_tool),
                target_tool,
            )
        except Exception as exc:  # pragma: no cover - exercised via result contract
            results[target_tool] = {"error": str(exc)}
            exit_code = 1

    if len(targets) == 1:
        print(json.dumps(results[targets[0]], indent=2))
    else:
        print(json.dumps(results, indent=2))

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
