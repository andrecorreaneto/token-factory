#!/usr/bin/env python3
"""Runnable TokenFactory usage patterns for OCI Compute instances."""

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def import_token_factory():
    try:
        import token_factory  # type: ignore

        return token_factory
    except ModuleNotFoundError:
        repo_root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "token_factory",
            repo_root / "__init__.py",
            submodule_search_locations=[str(repo_root)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["token_factory"] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module


token_factory = import_token_factory()


TOKEN_BACKED_COMMANDS = {
    "oauth",
    "userid",
    "oracle-database",
    "oci-service",
}


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.command in TOKEN_BACKED_COMMANDS:
        return run_token_backed_command(args)
    if args.command == "oci-credential-oauth":
        return run_oci_credential_oauth(args)
    raise ValueError(f"Unsupported command: {args.command}")


def parse_args(argv: Optional[list[str]] = None):
    parser = argparse.ArgumentParser(
        description="Run TokenFactory usage patterns from an OCI Compute instance.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_token_command(
        subparsers,
        "oauth",
        "Validate the incoming caller assertion, authorize scope, and request an OAuth token.",
        scope_required=True,
    )
    add_token_command(
        subparsers,
        "userid",
        "Validate the incoming caller assertion and print the resolved user id.",
        scope_required=False,
    )
    add_token_command(
        subparsers,
        "oracle-database",
        "Validate and authorize the caller, then request an Oracle Database scoped token.",
        scope_required=True,
    )
    add_token_command(
        subparsers,
        "oci-service",
        "Validate the caller and build an OCI TokenExchangeSigner.",
        scope_required=False,
    )

    oci_parser = subparsers.add_parser(
        "oci-credential-oauth",
        help="Use get_token_with_oci_credential() for OCI-authenticated OAuth exchange.",
    )
    oci_parser.add_argument("--scope", help="OAuth scope to request.")
    oci_parser.add_argument(
        "--profile",
        default="DEFAULT",
        help="OCI CLI profile name when --credential-json-file is not used.",
    )
    oci_parser.add_argument(
        "--credential-json-file",
        help="Path to a signer credential JSON object.",
    )
    oci_parser.add_argument("--dry-run", action="store_true", help="Print the call shape without exchanging tokens.")
    oci_parser.add_argument("--show-token", action="store_true", help="Print full token values instead of redacted previews.")

    return parser.parse_args(argv)


def add_token_command(subparsers, name: str, help_text: str, *, scope_required: bool) -> None:
    command = subparsers.add_parser(name, help=help_text)
    command.add_argument("--access-token", help="Incoming caller assertion string.")
    command.add_argument("--access-token-file", help="File containing the incoming caller assertion.")
    command.add_argument(
        "--client-key",
        required=True,
        help="Configured hosting component key in the oauth_apps map.",
    )
    command.add_argument(
        "--oauth-apps-json-file",
        help="Path to an oauth_apps JSON object. If omitted, TOKEN_FACTORY_OAUTH_APPS_JSON is used for real runs.",
    )
    command.add_argument("--scope", required=scope_required, help="Downstream requested scope.")
    command.add_argument("--dry-run", action="store_true", help="Print the call shape without exchanging tokens.")
    command.add_argument("--show-token", action="store_true", help="Print full token values instead of redacted previews.")


def run_token_backed_command(args) -> int:
    access_token, credential_source = resolve_access_token(args)
    if args.dry_run:
        print_json(
            {
                "method": "TokenFactory.get_token",
                "token_type": args.command,
                "scope": args.scope,
                "credential_source": credential_source,
                "client_key": args.client_key,
            }
        )
        return 0

    factory = token_factory.TokenFactory(oauth_apps=resolve_oauth_apps(args))
    result = factory.get_token(
        access_token,
        token_type=args.command,
        scope=args.scope,
        client_key=args.client_key,
    )
    print_json(serialize_result(args.command, result, show_token=args.show_token))
    return 0


def run_oci_credential_oauth(args) -> int:
    credential, credential_source = resolve_oci_credential(args)
    if args.dry_run:
        payload = {
            "method": "TokenFactory.get_token_with_oci_credential",
            "scope": args.scope,
            "credential_source": credential_source,
        }
        if credential_source == "oci-profile":
            payload["profile"] = credential
        else:
            payload["credential_fields"] = sorted(credential.keys())
        print_json(payload)
        return 0

    factory = token_factory.TokenFactory()
    result = factory.get_token_with_oci_credential(credential, scope=args.scope)
    print_json(serialize_oauth_result(result, show_token=args.show_token))
    return 0


def resolve_access_token(args) -> tuple[str, str]:
    if args.access_token:
        return args.access_token, "inline"
    if args.access_token_file:
        return Path(args.access_token_file).read_text(encoding="utf-8").strip(), "file"
    env_value = os.getenv("CALLER_ACCESS_TOKEN")
    if env_value:
        return env_value, "CALLER_ACCESS_TOKEN"
    raise ValueError("Provide --access-token, --access-token-file, or CALLER_ACCESS_TOKEN.")


def resolve_oauth_apps(args) -> Dict[str, Any]:
    if args.oauth_apps_json_file:
        with open(args.oauth_apps_json_file, "r", encoding="utf-8") as handle:
            return json.load(handle)
    env_value = os.getenv("TOKEN_FACTORY_OAUTH_APPS_JSON")
    if env_value:
        return json.loads(env_value)
    raise ValueError("Provide --oauth-apps-json-file or TOKEN_FACTORY_OAUTH_APPS_JSON.")


def resolve_oci_credential(args) -> tuple[Any, str]:
    if args.credential_json_file:
        with open(args.credential_json_file, "r", encoding="utf-8") as handle:
            return json.load(handle), "signer-dict"
    return args.profile, "oci-profile"


def serialize_result(command: str, result: Any, *, show_token: bool) -> Dict[str, Any]:
    if command == "oracle-database":
        token, private_key_pem, expires_in, token_type, issued_token_type = result
        return {
            "issued_token_type": issued_token_type,
            "token": token if show_token else redact_token(token),
            "private_key_pem_present": bool(private_key_pem),
            "expires_in": expires_in,
            "token_type": token_type,
        }
    if command == "oci-service":
        return {
            "issued_token_type": "oci-service",
            "signer_type": type(result).__name__,
            "created": True,
        }
    if command == "userid":
        return result
    return serialize_oauth_result(result, show_token=show_token)


def serialize_oauth_result(result: Dict[str, Any], *, show_token: bool) -> Dict[str, Any]:
    payload = dict(result)
    if "token" in payload and not show_token:
        payload["token"] = redact_token(payload["token"])
    return payload


def redact_token(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 16:
        return "<redacted>"
    return f"{value[:8]}...{value[-8:]}"


def print_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print_json({"error": str(exc)})
        raise SystemExit(1)
