#!/usr/bin/env python3
"""Select ordered web pentest modules from scope/auth traits."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

BASE_MODULES = ["surface-map", "server-integrity"]
FINAL_MODULE = "evidence-reporting"


def read_text(path: str | None) -> str:
    if not path:
        return ""
    candidate = Path(path)
    return candidate.read_text(encoding="utf-8") if candidate.exists() else ""


def add_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Select openghost-skill pentest modules")
    parser.add_argument("--url", default="")
    parser.add_argument("--scope")
    parser.add_argument("--auth")
    parser.add_argument("--traits", default="", help="Comma-separated observed traits")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    haystack = "\n".join([args.url, read_text(args.scope), read_text(args.auth), args.traits]).lower()
    traits = {part.strip().lower() for part in args.traits.split(",") if part.strip()}

    modules = list(BASE_MODULES)
    has_auth = bool(re.search(r"\b(form|bearer|token|cookie|api[-_ ]?key|oauth|jwt|role|admin|user)\b", haystack))
    multiple_roles = len(re.findall(r"\b(role|admin|manager|user|guest|tester)\b", haystack)) >= 2
    has_api = bool(re.search(r"\b(api|openapi|swagger|graphql|websocket|soap|xml|json)\b", haystack))
    has_inputs = bool(re.search(r"\b(form|upload|import|webhook|callback|url parameter|query|json|xml|file|search|filter)\b", haystack))
    has_browser_policy = bool(re.search(r"\b(cors|csp|csrf|cookie|iframe|redirect|header|clickjack)\b", haystack))
    has_http_edge = bool(re.search(r"\b(cache|cdn|proxy|waf|host header|request smuggling)\b", haystack))
    has_business = bool(re.search(r"\b(payment|checkout|order|invite|approval|quota|credit|coupon|workflow|race|mass assignment)\b", haystack))

    if has_auth:
        add_once(modules, "session-auth")
    if has_auth or multiple_roles:
        add_once(modules, "access-control")
    if has_api or traits.intersection({"api", "graphql", "websocket", "soap"}):
        add_once(modules, "api-protocols")
    if has_inputs or traits.intersection({"forms", "uploads", "ssrf", "sqli", "xss"}):
        add_once(modules, "injection")
    if has_browser_policy or has_auth:
        add_once(modules, "browser-policy")
    if has_http_edge:
        add_once(modules, "http-edge")
    if has_business or multiple_roles:
        add_once(modules, "business-logic")

    add_once(modules, FINAL_MODULE)

    if args.format == "json":
        print(json.dumps(modules, indent=2))
    else:
        print("\n".join(modules))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
