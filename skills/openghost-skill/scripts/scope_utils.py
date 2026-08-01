#!/usr/bin/env python3
"""Dependency-free validation for the OpenGhost scope template."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REQUIRED_AUTHORIZATION_FIELDS = [
    "sponsor",
    "authorization_document",
    "test_window",
    "emergency_stop_contact",
    "emergency_stop_phrase",
    "communication_channel",
]


def scalar(text: str, key: str) -> str:
    match = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.*?)\s*$", text)
    if not match:
        return ""
    return match.group(1).strip().strip("'\"")


def section(text: str, name: str) -> str:
    match = re.search(
        rf"(?m)^{re.escape(name)}\s*:\s*$\n(?P<body>(?:^[ \t]+[^\n]*(?:\n|$))*)",
        text,
    )
    return match.group("body") if match else ""


def list_values(text: str, name: str) -> list[str]:
    return [
        match.group(1).strip().strip("'\"")
        for match in re.finditer(r"(?m)^\s*-\s+(.+?)\s*$", section(text, name))
        if match.group(1).strip()
    ]


def bool_in_section(text: str, parent: str, key: str) -> bool | None:
    value = scalar(section(text, parent), key).lower()
    if value in {"true", "yes", "1"}:
        return True
    if value in {"false", "no", "0"}:
        return False
    return None


def parse_window(value: str) -> tuple[datetime, datetime] | None:
    try:
        start_text, end_text = value.split("/", 1)

        def parse(value_to_parse: str) -> datetime:
            parsed = datetime.fromisoformat(value_to_parse.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        return parse(start_text), parse(end_text)
    except (TypeError, ValueError):
        return None


def host_allowed(host: str, patterns: list[str]) -> bool:
    normalized = host.lower().rstrip(".")
    return any(fnmatch.fnmatchcase(normalized, pattern.lower().rstrip(".")) for pattern in patterns)


def validate_scope_file(
    path: Path,
    target_url: str = "",
    *,
    require_review: bool = True,
    enforce_window: bool = True,
    required_gates: list[str] | None = None,
) -> dict[str, Any]:
    issues: list[str] = []
    warnings: list[str] = []
    if not path.is_file():
        return {"passed": False, "issues": [f"scope file not found: {path}"], "warnings": []}
    text = path.read_text(encoding="utf-8")
    if re.search(r"\bTODO\b", text):
        issues.append("scope contains TODO placeholders")
    reviewed = bool_in_section(text, "authorization", "reviewed")
    if require_review and reviewed is not True:
        issues.append("authorization.reviewed must be true")
    auth = section(text, "authorization")
    for field in REQUIRED_AUTHORIZATION_FIELDS:
        if not scalar(auth, field):
            issues.append(f"authorization.{field} is required")
    window_value = scalar(auth, "test_window")
    window = parse_window(window_value)
    if window_value and not window:
        issues.append("authorization.test_window must be an ISO-8601 start/end range")
    elif window:
        start, end = window
        if start >= end:
            issues.append("authorization.test_window start must be before end")
        elif enforce_window:
            now = datetime.now(timezone.utc)
            if now < start or now > end:
                issues.append("current time is outside authorization.test_window")

    hosts = list_values(text, "allowed_hosts")
    if not hosts:
        issues.append("allowed_hosts must contain at least one host")
    ports: list[int] = []
    for value in list_values(text, "allowed_ports"):
        try:
            port = int(value)
        except ValueError:
            issues.append(f"invalid allowed port: {value}")
            continue
        if not 1 <= port <= 65535:
            issues.append(f"allowed port is outside 1-65535: {port}")
        else:
            ports.append(port)
    if not ports:
        issues.append("allowed_ports must contain at least one port")

    effective_target = target_url or scalar(text, "target_url")
    parsed = urlparse(effective_target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        issues.append("target_url must be an absolute HTTP(S) URL")
    elif hosts and not host_allowed(parsed.hostname, hosts):
        issues.append(f"target host is not allowed: {parsed.hostname}")
    elif ports:
        try:
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            issues.append("target_url contains an invalid port")
        else:
            if target_port not in ports:
                issues.append(f"target port is not allowed: {target_port}")

    rate = scalar(section(text, "rate_limits"), "requests_per_second")
    concurrency = scalar(section(text, "rate_limits"), "max_concurrent_requests")
    for label, value in [("requests_per_second", rate), ("max_concurrent_requests", concurrency)]:
        try:
            if float(value) <= 0:
                raise ValueError
        except ValueError:
            issues.append(f"rate_limits.{label} must be a positive number")

    for gate in required_gates or []:
        if bool_in_section(text, "active_testing", gate) is not True:
            issues.append(f"active_testing.{gate} must be true for this operation")
    if bool_in_section(text, "data_handling", "cleanup_required") is None:
        warnings.append("data_handling.cleanup_required should be explicitly true or false")
    return {
        "passed": not issues,
        "scope": str(path.resolve()),
        "target_url": effective_target,
        "reviewed": reviewed is True,
        "issues": issues,
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an OpenGhost authorization and scope file")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--target-url", default="")
    parser.add_argument("--allow-outside-window", action="store_true")
    parser.add_argument("--require-gate", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = validate_scope_file(
        Path(args.scope).expanduser().resolve(),
        args.target_url,
        enforce_window=not args.allow_outside_window,
        required_gates=args.require_gate,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Scope validation: {'PASSED' if result['passed'] else 'FAILED'}")
        for issue in result["issues"]:
            print(f"- error: {issue}")
        for warning in result["warnings"]:
            print(f"- warning: {warning}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
