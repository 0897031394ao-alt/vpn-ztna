#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx


DEFAULT_BASE_URL = "http://localhost:8000"


def login(base_url: str, username: str, password: str) -> str:
    resp = httpx.post(
        f"{base_url}/api/v1/auth/login",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"Login failed: HTTP {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    token = data.get("access_token")
    if not token:
        print("Login response has no access_token", file=sys.stderr)
        sys.exit(1)
    return token


def get_my_policy_explain(base_url: str, token: str) -> Dict[str, Any]:
    resp = httpx.get(
        f"{base_url}/api/v1/peers/my/policy-explain",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )

    if resp.status_code == 404:
        print("No provisioned peer found for current user.")
        sys.exit(2)

    if resp.status_code != 200:
        print(
            f"Failed to get policy explain: HTTP {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    return resp.json()


def download_my_config(base_url: str, token: str) -> tuple[str, str]:
    resp = httpx.get(
        f"{base_url}/api/v1/peers/my/config",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )

    if resp.status_code == 404:
        print("No provisioned peer found for current user.")
        sys.exit(2)

    if resp.status_code != 200:
        print(
            f"Failed to download config: HTTP {resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    content_disposition = resp.headers.get("Content-Disposition", "")
    filename = "wg0.conf"
    if "filename=" in content_disposition:
        filename = content_disposition.split("filename=", 1)[1].strip().strip('"')

    return filename, resp.text


def print_summary(explain: Dict[str, Any]) -> None:
    summary = explain.get("summary", {})
    peer_id = explain.get("peer_id")
    vpn_ip = explain.get("vpn_ip")
    effective_access_mode = summary.get("effective_access_mode")
    has_full_internet_access = summary.get("has_full_internet_access")
    allowed_count = summary.get("allowed_count")
    allowed_policies_count = summary.get("allowed_policies_count")
    denied_policies_count = summary.get("denied_policies_count")

    print(f"Peer ID: {peer_id}")
    print(f"VPN IP:  {vpn_ip}")
    print()
    print("Access summary:")
    print(f"  Mode:                  {effective_access_mode}")
    print(f"  Full internet access:  {has_full_internet_access}")
    print(f"  Allowed CIDRs count:   {allowed_count}")
    print(f"  Allow policies count:  {allowed_policies_count}")
    print(f"  Deny policies count:   {denied_policies_count}")


def print_steps(explain: Dict[str, Any]) -> None:
    steps: List[Dict[str, Any]] = explain.get("steps") or []
    print()
    print("Policy steps:")
    for idx, s in enumerate(steps, start=1):
        print(f"- Step #{idx}")
        print(f"    policy_id:     {s.get('policy_id')}")
        print(f"    name:          {s.get('name')}")
        print(f"    scope:         {s.get('scope')}")
        print(f"    effect:        {s.get('effect')}")
        print(f"    resource_cidr: {s.get('resource_cidr')}")
        print(f"    before:        {s.get('before')}")
        print(f"    after:         {s.get('after')}")
        print()


def cmd_show_policy(args: argparse.Namespace) -> None:
    token = login(args.base_url, args.username, args.password)
    explain = get_my_policy_explain(args.base_url, token)
    print_summary(explain)
    if args.show_steps:
        print_steps(explain)


def cmd_get_config(args: argparse.Namespace) -> None:
    token = login(args.base_url, args.username, args.password)
    suggested_filename, config_text = download_my_config(args.base_url, token)

    output_path = Path(args.output or suggested_filename)
    output_path.write_text(config_text, encoding="utf-8")

    print(f"Config saved to: {output_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Minimal VPN-ZTNA CLI for end users."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    show_policy = subparsers.add_parser(
        "show-policy",
        help="Show policy summary for current user",
    )
    show_policy.add_argument("--username", required=True, help="Username for login")
    show_policy.add_argument("--password", required=True, help="Password for login")
    show_policy.add_argument(
        "--show-steps",
        action="store_true",
        help="Also show detailed policy steps",
    )
    show_policy.set_defaults(func=cmd_show_policy)

    get_config = subparsers.add_parser(
        "get-config",
        help="Download WireGuard config for current user",
    )
    get_config.add_argument("--username", required=True, help="Username for login")
    get_config.add_argument("--password", required=True, help="Password for login")
    get_config.add_argument(
        "--output",
        help="Output file path (default: filename from server or wg0.conf)",
    )
    get_config.set_defaults(func=cmd_get_config)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
