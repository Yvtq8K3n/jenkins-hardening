#!/usr/bin/env python3
"""Gather evidence from a Jenkins instance via REST API for hardening audits."""

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

# Load .env file if it exists
if load_dotenv:
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)

DEFAULT_TIMEOUT = 5.0


@dataclass
class ApiResponse:
    """Structured response from a jenkins_api subcommand."""
    status: str  # 'ok', 'forbidden', 'error'
    data: dict[str, Any] | None = None
    message: str | None = None


def get_auth_from_env_or_args(username: str | None, token: str | None) -> tuple[str, str] | None:
    """Build auth tuple from args or env vars. Args take precedence."""
    if username or token:
        user = username or os.getenv("JENKINS_USER")
        pwd = token or os.getenv("JENKINS_TOKEN")
        if user and pwd:
            return (user, pwd)
        return None

    # Check env vars only
    user = os.getenv("JENKINS_USER")
    pwd = os.getenv("JENKINS_TOKEN")
    if user and pwd:
        return (user, pwd)
    return None


def make_request(
    url: str,
    timeout: float,
    verify_tls: bool,
    auth: tuple[str, str] | None = None,
) -> ApiResponse:
    """Make an authenticated GET request, returning a structured response."""
    try:
        resp = requests.get(url, timeout=timeout, verify=verify_tls, auth=auth)
    except requests.exceptions.RequestException as exc:
        return ApiResponse(status="error", message=f"Request failed: {exc}")

    if resp.status_code == 401:
        return ApiResponse(status="forbidden", message="Unauthorized (invalid credentials)")
    elif resp.status_code == 403:
        return ApiResponse(status="forbidden", message="Forbidden (insufficient permissions)")
    elif resp.status_code >= 400:
        return ApiResponse(status="error", message=f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except ValueError:
        return ApiResponse(status="error", message="Invalid JSON response")

    return ApiResponse(status="ok", data=data)


def cmd_info(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /api/json (root info)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "api/json")
    return make_request(url, timeout, verify_tls, auth)


def cmd_anon_check(jenkins_url: str, timeout: float, verify_tls: bool) -> ApiResponse:
    """Fetch /api/json without auth to test anonymous access."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "api/json")
    return make_request(url, timeout, verify_tls, auth=None)


def cmd_crumb(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /crumbIssuer/api/json (CSRF token issuer)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "crumbIssuer/api/json")
    return make_request(url, timeout, verify_tls, auth)


def cmd_plugins(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /pluginManager/api/json (plugin list with versions, update status)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "pluginManager/api/json?depth=1")
    return make_request(url, timeout, verify_tls, auth)


def cmd_nodes(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /computer/api/json (node/agent info including executors, launcher type)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "computer/api/json?depth=1")
    return make_request(url, timeout, verify_tls, auth)


def cmd_people(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /asynchPeople/api/json (user account list)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "asynchPeople/api/json")
    return make_request(url, timeout, verify_tls, auth)


def cmd_whoami(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch /whoAmI/api/json (authenticated user details and authorities)."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "whoAmI/api/json")
    return make_request(url, timeout, verify_tls, auth)


def cmd_signup_check(jenkins_url: str, timeout: float, verify_tls: bool) -> ApiResponse:
    """Check /signup without auth to test if self-registration is exposed."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "signup")
    try:
        resp = requests.get(url, timeout=timeout, verify=verify_tls, allow_redirects=False)
    except requests.exceptions.RequestException as exc:
        return ApiResponse(status="error", message=f"Request failed: {exc}")

    # 200/302 = signup may be available; 404 = hidden; 403 = disabled
    data = {"status_code": resp.status_code, "likely_available": resp.status_code in (200, 302)}
    return ApiResponse(status="ok", data=data)


def cmd_credentials(jenkins_url: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch global credential domains and metadata."""
    url = urljoin(jenkins_url.rstrip("/") + "/", "credentials/store/system/domain/_/api/json")
    return make_request(url, timeout, verify_tls, auth)


def cmd_raw(jenkins_url: str, path: str, timeout: float, verify_tls: bool, auth: tuple[str, str] | None) -> ApiResponse:
    """Fetch an arbitrary REST path."""
    url = urljoin(jenkins_url.rstrip("/") + "/", path.lstrip("/"))
    return make_request(url, timeout, verify_tls, auth)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jenkins-url", help="Jenkins base URL (default: env var JENKINS_URL)")
    parser.add_argument("--username", help="Username for auth (default: env var JENKINS_USER)")
    parser.add_argument("--token", help="API token for auth (default: env var JENKINS_TOKEN)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("info", help="Fetch /api/json (root Jenkins info)")
    subparsers.add_parser("anon-check", help="Fetch /api/json without auth (test anonymous access)")
    subparsers.add_parser("crumb", help="Fetch /crumbIssuer/api/json (CSRF token issuer)")
    subparsers.add_parser("plugins", help="Fetch /pluginManager/api/json (plugins)")
    subparsers.add_parser("nodes", help="Fetch /computer/api/json (nodes/agents)")
    subparsers.add_parser("people", help="Fetch /asynchPeople/api/json (users)")
    subparsers.add_parser("whoami", help="Fetch /whoAmI/api/json (current user)")
    subparsers.add_parser("signup-check", help="Check if /signup is available")
    subparsers.add_parser("credentials", help="Fetch global credential store metadata")
    raw_parser = subparsers.add_parser("raw", help="Fetch arbitrary REST path")
    raw_parser.add_argument("path", help="REST API path (e.g. queue/api/json)")

    args = parser.parse_args()

    jenkins_url = args.jenkins_url or os.getenv("JENKINS_URL")
    if not jenkins_url:
        parser.error("Jenkins URL required (--jenkins-url or JENKINS_URL env var)")

    auth = get_auth_from_env_or_args(args.username, args.token)
    verify_tls = not args.insecure

    # Dispatch subcommand
    if args.command == "info":
        result = cmd_info(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "anon-check":
        result = cmd_anon_check(jenkins_url, args.timeout, verify_tls)
    elif args.command == "crumb":
        result = cmd_crumb(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "plugins":
        result = cmd_plugins(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "nodes":
        result = cmd_nodes(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "people":
        result = cmd_people(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "whoami":
        result = cmd_whoami(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "signup-check":
        result = cmd_signup_check(jenkins_url, args.timeout, verify_tls)
    elif args.command == "credentials":
        result = cmd_credentials(jenkins_url, args.timeout, verify_tls, auth)
    elif args.command == "raw":
        result = cmd_raw(jenkins_url, args.path, args.timeout, verify_tls, auth)
    else:
        parser.error(f"Unknown command: {args.command}")

    # Output as JSON
    print(json.dumps(asdict(result)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
