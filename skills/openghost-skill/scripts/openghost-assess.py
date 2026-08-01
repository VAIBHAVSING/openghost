#!/usr/bin/env python3
"""Autonomous first-pass OpenGhost assessment orchestrator.

This helper intentionally creates leads, not confirmed findings. It runs
low-impact templates through the launcher, registers raw outputs as evidence,
adds likely findings for high-value signals, and writes an assessment summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scope_utils import validate_scope_file


SEVERITIES = {"critical", "high", "medium", "low", "info"}
LEAD_SEVERITIES = {"critical", "high", "medium"}
DEFAULT_ENDPOINTS = ["/"]
CACHE_SCHEMA_VERSION = 1


@dataclass
class Step:
    tool: str
    args: list[str]
    module: str
    reason: str


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def slugify(value: str, default: str = "item") -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    return slug or default


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        die(f"invalid JSON in {path}: {exc}")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_fingerprint(path: Path) -> str:
    return sha256_file(path) if path.exists() and path.is_file() else "missing"


def load_manifest(skill_dir: Path) -> dict[str, dict[str, Any]]:
    manifest = skill_dir / "scripts" / "pentest" / "manifest.json"
    data = load_json(manifest, {})
    return {item["name"]: item for item in data.get("scripts", [])}


def resolve_engagement_dir(args: argparse.Namespace) -> Path | None:
    home = Path(args.openghost_home).expanduser().resolve()
    if getattr(args, "dir", None):
        return Path(args.dir).expanduser().resolve()
    if getattr(args, "engagement", None):
        return (home / "engagements" / slugify(args.engagement)).resolve()
    current = home / "current"
    if current.exists():
        value = current.read_text(encoding="utf-8").strip()
        if value:
            return Path(value).expanduser().resolve()
    return None


def target_from_engagement(root: Path | None) -> str:
    if not root:
        return ""
    data = load_json(root / "engagement.json", {})
    return str(data.get("target_url") or "")


def host_to_container(path: Path, workspace: Path) -> str:
    path = path.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    try:
        rel = path.relative_to(workspace)
    except ValueError:
        die(f"path is outside OPENGHOST_WORKSPACE: {path}")
    return "/workspace" if str(rel) == "." else "/workspace/" + rel.as_posix()


def command_text(argv: list[str]) -> str:
    redacted: list[str] = []
    redact_next = False
    for item in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(item)
        if item in {"--token", "--cookies", "Authorization", "Cookie"}:
            redact_next = True
    return " ".join(shlex.quote(part) for part in redacted)


def resolve_auth_token(args: argparse.Namespace) -> str:
    sources = sum(
        bool(value)
        for value in (
            getattr(args, "token", None),
            getattr(args, "token_env", None),
            getattr(args, "token_file", None),
        )
    )
    if sources > 1:
        die("use only one of --token-env, --token-file, or the deprecated --token")
    if getattr(args, "token_env", None):
        name = args.token_env
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            die(f"invalid environment variable name: {name}")
        value = os.environ.get(name, "")
        if not value:
            die(f"environment variable {name} is empty or unset")
        return value
    if getattr(args, "token_file", None):
        path = Path(args.token_file).expanduser().resolve()
        if not path.is_file():
            die(f"token file not found: {path}")
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            die(f"token file is empty: {path}")
        return value
    return str(getattr(args, "token", None) or "")


def run_launcher(args: argparse.Namespace, argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["OPENGHOST_HOME"] = str(Path(args.openghost_home).expanduser().resolve())
    env["OPENGHOST_WORKSPACE"] = str(Path(args.workspace).expanduser().resolve())
    if getattr(args, "auth_token", ""):
        env["OPENGHOST_TARGET_BEARER_TOKEN"] = args.auth_token
    proc = subprocess.run(
        [args.launcher, *argv],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "").strip() or f"command failed: {command_text(argv)}")
    return proc


def parse_saved_id(stdout: str, key: str) -> str:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = data.get(key)
        if value:
            return str(value)
    return ""


def normalized_severity(value: Any) -> str:
    severity = str(value or "info").split()[0].strip().lower()
    return severity if severity in SEVERITIES else "info"


def signal_location(signal: dict[str, Any]) -> str:
    for key in ("url", "endpoint", "path", "template", "reference", "source"):
        value = signal.get(key)
        if value:
            return str(value)
    return ""


def signal_asset(signal: dict[str, Any], target_url: str) -> str:
    return signal_location(signal) or target_url


def signal_type(signal: dict[str, Any]) -> str:
    return str(signal.get("type") or signal.get("title") or "")


def signal_title(tool: str, signal: dict[str, Any]) -> str:
    raw = signal.get("title") or signal.get("type") or "security signal"
    title = str(raw).replace("_", " ").replace("-", " ").strip().title()
    location = signal_location(signal)
    if location:
        short = location if len(location) <= 90 else location[:87] + "..."
        title = f"{title} at {short}"
    return f"{title} ({tool})"


def signal_key(tool: str, signal: dict[str, Any], target_url: str) -> tuple[str, str, str]:
    return (tool, signal_type(signal), signal_asset(signal, target_url))


def existing_finding_keys(root: Path) -> set[tuple[str, str, str]]:
    findings = load_json(root / "state" / "findings.json", [])
    keys: set[tuple[str, str, str]] = set()
    for item in findings if isinstance(findings, list) else []:
        notes = str(item.get("notes") or "")
        source_tool = ""
        source_type = ""
        for line in notes.splitlines():
            if line.startswith("source_tool:"):
                source_tool = line.split(":", 1)[1].strip()
            elif line.startswith("source_type:"):
                source_type = line.split(":", 1)[1].strip()
        asset = item.get("affected_asset") or {}
        keys.add((source_tool, source_type, asset.get("asset") or asset.get("url") or ""))
    return keys


def extract_endpoints(report_path: Path, target_url: str) -> list[str]:
    data = load_json(report_path, {})
    endpoints: list[str] = []
    target_host = urlparse(target_url).netloc
    for item in data.get("findings", []):
        if not isinstance(item, dict):
            continue
        candidate = item.get("url") or item.get("path") or item.get("endpoint")
        if not candidate:
            continue
        text = str(candidate)
        if text.startswith("http://") or text.startswith("https://"):
            parsed = urlparse(text)
            if target_host and parsed.netloc != target_host:
                continue
            text = parsed.path or "/"
            if parsed.query:
                text += "?" + parsed.query
        if not text.startswith("/"):
            continue
        if text not in endpoints:
            endpoints.append(text)
        if len(endpoints) >= 12:
            break
    return endpoints or list(DEFAULT_ENDPOINTS)


def build_base_steps(args: argparse.Namespace, target_url: str, manifest: dict[str, dict[str, Any]]) -> list[Step]:
    steps = [
        Step("web-baseline", ["--target-url", target_url], manifest["web-baseline"]["module"], "baseline headers and HTTP methods"),
        Step("api-inventory", ["--target-url", target_url], manifest["api-inventory"]["module"], "common API/docs endpoint discovery"),
    ]
    if args.mode in {"standard", "deep"}:
        steps.append(
            Step(
                "forced-browsing-check",
                ["--base-url", target_url],
                manifest["forced-browsing-check"]["module"],
                "small read-only administrative path probe",
            )
        )
    return steps


def build_dynamic_steps(
    args: argparse.Namespace,
    target_url: str,
    manifest: dict[str, dict[str, Any]],
    endpoints: list[str],
) -> list[Step]:
    steps: list[Step] = []
    if args.mode in {"standard", "deep"}:
        cors_args = ["--base-url", target_url, "--endpoints", *endpoints[:12]]
        steps.append(Step("cors-check", cors_args, manifest["cors-check"]["module"], "CORS behavior on discovered endpoints"))
    if args.mode == "deep" or args.include_probes:
        xss_args = ["--base-url", target_url, "--params", "/search?q=FUZZ", "/?q=FUZZ"]
        steps.append(Step("xss-check", xss_args, manifest["xss-check"]["module"], "low-impact reflected marker probes"))
    return steps


def step_output_path(run_dir: Path, step: Step) -> Path:
    return run_dir / f"{step.tool}.json"


def cache_key(args: argparse.Namespace, root: Path, step: Step) -> str:
    skill_dir = Path(args.skill_dir)
    template = skill_dir / "scripts" / "pentest" / f"{step.tool.replace('-', '_')}.py"
    if not template.exists():
        template = skill_dir / "scripts" / "pentest" / f"{step.tool}.py"
    payload = {
        "schema": CACHE_SCHEMA_VERSION,
        "tool": step.tool,
        "module": step.module,
        "args": step.args,
        "limits": {
            "max_requests": args.max_requests,
            "rate_ms": args.rate_ms,
            "timeout": args.timeout,
        },
        "scope_sha256": file_fingerprint(root / "scope.yaml"),
        "template_sha256": file_fingerprint(template),
        "helper_sha256": file_fingerprint(skill_dir / "scripts" / "pentest" / "og_pentest.py"),
        # A token changes the authorization context, but its value is never persisted.
        "auth_fingerprint": sha256_bytes(
            json.dumps(
                {"bearer": args.auth_token, "cookies": args.target_cookies},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        if args.authenticated
        else "anonymous",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(canonical)


def cache_paths(root: Path, key: str) -> tuple[Path, Path]:
    cache_dir = root / "cache" / "assessment"
    return cache_dir / f"{key}.json", cache_dir / f"{key}.report.json"


def cache_enabled(args: argparse.Namespace) -> bool:
    if args.no_cache:
        return False
    if args.authenticated and not args.cache_authenticated:
        return False
    return True


def existing_evidence_id(root: Path, evidence_id: str) -> bool:
    if not evidence_id:
        return False
    records = load_json(root / "state" / "evidence.json", [])
    if not isinstance(records, list):
        return False
    return any(isinstance(item, dict) and item.get("id") == evidence_id for item in records)


def read_step_cache(args: argparse.Namespace, root: Path, run_dir: Path, step: Step) -> dict[str, Any] | None:
    if not cache_enabled(args) or args.refresh:
        return None
    key = cache_key(args, root, step)
    metadata_path, cached_report = cache_paths(root, key)
    if not metadata_path.is_file() or not cached_report.is_file():
        return None
    metadata = load_json(metadata_path, {})
    created_epoch = float(metadata.get("created_epoch") or 0)
    age_seconds = max(0, int(time.time() - created_epoch))
    if args.cache_ttl >= 0 and age_seconds > args.cache_ttl:
        return None
    if file_fingerprint(cached_report) != metadata.get("report_sha256"):
        return None
    evidence_id = str(metadata.get("evidence_id") or "")
    if not existing_evidence_id(root, evidence_id):
        return None
    output = step_output_path(run_dir, step)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cached_report, output)
    data = load_json(output, {})
    signals = data.get("findings", []) if isinstance(data, dict) else []
    return {
        "tool": step.tool,
        "module": step.module,
        "reason": step.reason,
        "command": str(metadata.get("command") or "cached deterministic result"),
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "stdout": "",
        "stderr": "",
        "report_path": str(output),
        "signal_count": len(signals) if isinstance(signals, list) else 0,
        "signals": signals if isinstance(signals, list) else [],
        "evidence_id": evidence_id,
        "cache_hit": True,
        "cache_age_seconds": age_seconds,
        "cache_key": key,
    }


def write_step_cache(args: argparse.Namespace, root: Path, result: dict[str, Any]) -> None:
    if not cache_enabled(args):
        return
    key = str(result.get("cache_key") or "")
    report_path = Path(str(result.get("report_path") or ""))
    if not key or not report_path.is_file() or not result.get("evidence_id"):
        return
    metadata_path, cached_report = cache_paths(root, key)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(report_path, cached_report)
    write_json(
        metadata_path,
        {
            "schema_version": CACHE_SCHEMA_VERSION,
            "created_at": utc_now(),
            "created_epoch": time.time(),
            "tool": result["tool"],
            "module": result["module"],
            "command": result["command"],
            "evidence_id": result["evidence_id"],
            "report_sha256": sha256_file(cached_report),
        },
    )


def execute_step(
    args: argparse.Namespace,
    root: Path,
    run_dir: Path,
    workspace: Path,
    step: Step,
) -> dict[str, Any]:
    cached = read_step_cache(args, root, run_dir, step)
    if cached is not None:
        return cached
    output = step_output_path(run_dir, step)
    container_output = host_to_container(output, workspace)
    cmd_args = [
        "script",
        "run",
        step.tool,
        "--dir",
        str(root),
        "--",
        *step.args,
        "--max-requests",
        str(args.max_requests),
        "--rate-ms",
        str(args.rate_ms),
        "--timeout",
        str(args.timeout),
        "-o",
        container_output,
    ]
    started_at = utc_now()
    proc = run_launcher(args, cmd_args)
    data = load_json(output, {})
    signals = data.get("findings", []) if isinstance(data, dict) else []
    return {
        "tool": step.tool,
        "module": step.module,
        "reason": step.reason,
        "command": command_text(["openghost", *cmd_args]),
        "started_at": started_at,
        "completed_at": utc_now(),
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "report_path": str(output),
        "signal_count": len(signals) if isinstance(signals, list) else 0,
        "signals": signals if isinstance(signals, list) else [],
        "cache_hit": False,
        "cache_age_seconds": 0,
        "cache_key": cache_key(args, root, step),
    }


def register_evidence(args: argparse.Namespace, root: Path, result: dict[str, Any]) -> str:
    proc = run_launcher(
        args,
        [
            "evidence",
            "add",
            "--dir",
            str(root),
            "--path",
            result["report_path"],
            "--kind",
            "tool-output",
            "--title",
            f"Autonomous {result['tool']} output",
            "--module",
            result["module"],
            "--command",
            result["command"],
            "--notes",
            "Autonomous assessment signal output; validate before confirmed reporting.",
        ],
    )
    return parse_saved_id(proc.stdout, "saved")


def create_lead(
    args: argparse.Namespace,
    root: Path,
    tool: str,
    module: str,
    evidence_id: str,
    signal: dict[str, Any],
) -> str:
    severity = normalized_severity(signal.get("severity"))
    title = signal_title(tool, signal)
    asset = signal_asset(signal, args.target_url)
    notes = {
        "source_tool": tool,
        "source_type": signal_type(signal),
        "raw_signal": signal,
    }
    proc = run_launcher(
        args,
        [
            "finding",
            "add",
            "--dir",
            str(root),
            "--title",
            title,
            "--severity",
            severity,
            "--status",
            "likely",
            "--module",
            module,
            "--asset",
            asset,
            "--confidence",
            "60",
            "--evidence",
            evidence_id,
            "--summary",
            f"Autonomous assessment signal from {tool}. Validate manually before promoting to confirmed.",
            "--notes",
            "source_tool: "
            + tool
            + "\nsource_type: "
            + signal_type(signal)
            + "\nraw_signal: "
            + json.dumps(notes["raw_signal"], sort_keys=True, ensure_ascii=True)[:1600],
        ],
    )
    return parse_saved_id(proc.stdout, "saved")


def create_validation_todo(args: argparse.Namespace, root: Path, finding_id: str, module: str, title: str, severity: str) -> str:
    priority = "high" if severity in {"critical", "high"} else "medium"
    proc = run_launcher(
        args,
        [
            "todo",
            "add",
            "--dir",
            str(root),
            "--task",
            f"Validate autonomous lead {finding_id}: {title}",
            "--module",
            module,
            "--priority",
            priority,
            "--finding",
            finding_id,
        ],
    )
    return parse_saved_id(proc.stdout, "saved")


def register_assessment_artifact(args: argparse.Namespace, root: Path, summary_path: Path) -> str:
    proc = run_launcher(
        args,
        [
            "artifact",
            "add",
            "--dir",
            str(root),
            "--path",
            str(summary_path),
            "--kind",
            "inventory",
            "--title",
            "Autonomous assessment summary",
            "--module",
            "evidence-reporting",
        ],
    )
    return parse_saved_id(proc.stdout, "saved")


def record_partial_coverage(args: argparse.Namespace, root: Path, module: str) -> None:
    run_launcher(
        args,
        [
            "coverage",
            "set",
            "--dir",
            str(root),
            "--module",
            module,
            "--status",
            "partial",
            "--reason",
            "Automated first-pass signals only; complete module-specific hypothesis validation before closure.",
        ],
    )


def validate_scope(root: Path, confirmed: bool, args: argparse.Namespace) -> None:
    scope = root / "scope.yaml"
    if not confirmed:
        die("pass --confirm-scope-reviewed after independently reviewing the authorization and scope")
    gates: list[str] = []
    if args.mode in {"standard", "deep"}:
        gates.append("content_discovery")
    if args.mode == "deep" or args.include_probes:
        gates.append("reflected_marker_probes")
    result = validate_scope_file(scope, args.target_url, required_gates=gates)
    if not result["passed"]:
        details = "\n".join(f"- {issue}" for issue in result["issues"])
        die(f"scope validation failed:\n{details}")


def print_plan(args: argparse.Namespace, steps: list[Step], target_url: str) -> None:
    dynamic = []
    if args.mode in {"standard", "deep"}:
        dynamic.append({"tool": "cors-check", "reason": "runs after API inventory against discovered endpoints"})
    if args.mode == "deep" or args.include_probes:
        dynamic.append({"tool": "xss-check", "reason": "low-impact reflected marker probes"})
    plan = {
        "target_url": target_url,
        "mode": args.mode,
        "safety": "creates likely leads only; confirmed findings still require manual validation",
        "base_steps": [{"tool": s.tool, "module": s.module, "reason": s.reason, "args": s.args} for s in steps],
        "dynamic_steps": dynamic,
        "lead_severities": sorted(LEAD_SEVERITIES),
        "required_scope_gates": [
            *(["content_discovery"] if args.mode in {"standard", "deep"} else []),
            *(["reflected_marker_probes"] if args.mode == "deep" or args.include_probes else []),
        ],
        "cache_policy": "anonymous deterministic results reuse for 3600 seconds by default; authenticated reuse is opt-in",
    }
    if args.json:
        print(json.dumps(plan, indent=2))
        return
    print(f"Autonomous assessment plan for {target_url}")
    print(f"mode: {args.mode}")
    if plan["required_scope_gates"]:
        print("required scope gates: " + ", ".join(plan["required_scope_gates"]))
    for step in plan["base_steps"]:
        print(f"- {step['tool']} ({step['module']}): {step['reason']}")
    for step in dynamic:
        print(f"- {step['tool']}: {step['reason']}")
    print("Signals become likely findings only; confirmed findings still require evidence-backed validation.")
    print("Matching anonymous results use the local cache unless --refresh or --no-cache is passed to assess run.")


def command_plan(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.skill_dir))
    root = resolve_engagement_dir(args)
    target_url = args.target_url or target_from_engagement(root)
    if not target_url:
        die("assess plan requires --target-url or an active engagement with target_url")
    steps = build_base_steps(args, target_url, manifest)
    print_plan(args, steps, target_url)
    return 0


def command_run(args: argparse.Namespace) -> int:
    args.auth_token = resolve_auth_token(args)
    args.target_cookies = os.environ.get("OPENGHOST_TARGET_COOKIES", "")
    args.authenticated = bool(args.auth_token or args.target_cookies)
    manifest = load_manifest(Path(args.skill_dir))
    root = resolve_engagement_dir(args)
    if not root:
        die("assess run requires an active engagement, --engagement NAME, or --dir DIR")
    root = root.resolve()
    if not root.exists():
        die(f"engagement directory not found: {root}")
    target_url = args.target_url or target_from_engagement(root)
    if not target_url:
        die("assess run requires --target-url or engagement.json target_url")
    args.target_url = target_url
    validate_scope(root, args.confirm_scope_reviewed, args)

    workspace = Path(args.workspace).expanduser().resolve()
    run_dir = root / "runs" / f"assess-{timestamp_slug()}"
    run_dir.mkdir(parents=True, exist_ok=True)

    base_steps = build_base_steps(args, target_url, manifest)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    endpoints = list(args.endpoint or [])

    for step in base_steps:
        try:
            result = execute_step(args, root, run_dir, workspace, step)
            if not result.get("evidence_id"):
                result["evidence_id"] = register_evidence(args, root, result)
                write_step_cache(args, root, result)
            results.append(result)
            if step.tool == "api-inventory":
                endpoints.extend(item for item in extract_endpoints(Path(result["report_path"]), target_url) if item not in endpoints)
        except Exception as exc:  # noqa: BLE001
            errors.append({"tool": step.tool, "error": str(exc)})

    for step in build_dynamic_steps(args, target_url, manifest, endpoints or list(DEFAULT_ENDPOINTS)):
        try:
            result = execute_step(args, root, run_dir, workspace, step)
            if not result.get("evidence_id"):
                result["evidence_id"] = register_evidence(args, root, result)
                write_step_cache(args, root, result)
            results.append(result)
        except Exception as exc:  # noqa: BLE001
            errors.append({"tool": step.tool, "error": str(exc)})

    existing = existing_finding_keys(root)
    leads_created: list[dict[str, str]] = []
    todos_created: list[dict[str, str]] = []
    signal_counts: dict[str, int] = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    lead_budget = args.max_leads

    for result in results:
        evidence_id = result.get("evidence_id", "")
        if not evidence_id:
            continue
        for signal in result.get("signals", []):
            if not isinstance(signal, dict):
                continue
            severity = normalized_severity(signal.get("severity"))
            signal_counts[severity] = signal_counts.get(severity, 0) + 1
            if severity not in LEAD_SEVERITIES or lead_budget <= 0:
                continue
            key = signal_key(result["tool"], signal, target_url)
            if key in existing:
                continue
            finding_id = create_lead(args, root, result["tool"], result["module"], evidence_id, signal)
            if not finding_id:
                continue
            lead_budget -= 1
            existing.add(key)
            title = signal_title(result["tool"], signal)
            leads_created.append({"id": finding_id, "severity": severity, "title": title})
            todo_id = create_validation_todo(args, root, finding_id, result["module"], title, severity)
            if todo_id:
                todos_created.append({"id": todo_id, "finding_id": finding_id})

    successful_results = [item for item in results if item.get("evidence_id")]
    for module in sorted({str(item.get("module") or "") for item in successful_results if item.get("module")}):
        try:
            record_partial_coverage(args, root, module)
        except Exception as exc:  # noqa: BLE001
            errors.append({"tool": "coverage", "error": f"{module}: {exc}"})
    status = "failed" if not successful_results else "completed_with_errors" if errors else "completed"
    summary_path = run_dir / "assessment.json"
    summary = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "target_url": target_url,
        "engagement_dir": str(root),
        "run_dir": str(run_dir),
        "mode": args.mode,
        "status": status,
        "safety": {
            "confirmed_findings_created": 0,
            "lead_status": "likely",
            "note": "Autonomous outputs are leads and require manual validation before confirmed reporting.",
        },
        "steps": [
            {
                "tool": item["tool"],
                "module": item["module"],
                "report_path": item["report_path"],
                "evidence_id": item.get("evidence_id", ""),
                "signal_count": item["signal_count"],
                "cache_hit": bool(item.get("cache_hit")),
                "cache_age_seconds": int(item.get("cache_age_seconds") or 0),
            }
            for item in results
        ],
        "cache": {
            "enabled": cache_enabled(args),
            "authenticated_reuse": bool(args.cache_authenticated),
            "ttl_seconds": args.cache_ttl,
            "hits": sum(1 for item in results if item.get("cache_hit")),
            "misses": sum(1 for item in results if not item.get("cache_hit")),
            "note": "Authenticated output caching is opt-in; credentials are fingerprinted and never stored.",
        },
        "signal_counts": signal_counts,
        "leads_created": leads_created,
        "todos_created": todos_created,
        "errors": errors,
        "next_steps": [
            "Review likely findings and validate with exact request/response or browser evidence.",
            "Promote only evidence-backed issues to confirmed findings.",
            "Run module-specific checks for authenticated, role-based, and business-logic coverage.",
            "Use openghost context show as the compact resume point.",
            "Close every selected module as tested, skipped, or not-applicable before final reporting.",
        ],
    }
    write_json(summary_path, summary)
    if successful_results:
        summary["artifact_id"] = register_assessment_artifact(args, root, summary_path)
        write_json(summary_path, summary)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"assessment: {summary_path}")
        print(f"status: {summary['status']}")
        print(f"signals: {sum(signal_counts.values())}")
        print(f"likely leads created: {len(leads_created)}")
        print(f"validation todos created: {len(todos_created)}")
        print(f"cache: {summary['cache']['hits']} hit(s), {summary['cache']['misses']} miss(es)")
        if errors:
            print(f"errors: {len(errors)}")
    return 1 if not successful_results else 0


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--skill-dir", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--openghost-home", required=True)
    parser.add_argument("--dir")
    parser.add_argument("--engagement")
    parser.add_argument("--target-url")
    parser.add_argument("--mode", choices=["safe", "standard", "deep"], default="standard")
    parser.add_argument("--include-probes", action="store_true", help="Include low-impact reflected XSS marker probes.")
    parser.add_argument("--endpoint", action="append", help="Seed endpoint for dynamic checks. May be passed multiple times.")
    parser.add_argument("--token-env", help="Read a bearer token from this environment variable (recommended).")
    parser.add_argument("--token-file", help="Read a bearer token from a file outside committed source.")
    parser.add_argument("--token", help="Deprecated: bearer token on the command line; prefer --token-env or --token-file.")
    parser.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenGhost autonomous first-pass assessment")
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="Show the autonomous assessment plan without running tools.")
    add_common(plan)
    plan.set_defaults(func=command_plan)

    run = sub.add_parser("run", help="Run safe autonomous checks and create likely findings.")
    add_common(run)
    run.add_argument("--confirm-scope-reviewed", action="store_true")
    run.add_argument("--max-requests", type=int, default=40)
    run.add_argument("--rate-ms", type=int, default=250)
    run.add_argument("--timeout", type=float, default=10.0)
    run.add_argument("--max-leads", type=int, default=20)
    run.add_argument("--cache-ttl", type=int, default=3600, help="Reuse deterministic results for this many seconds (default: 3600).")
    run.add_argument("--no-cache", action="store_true", help="Disable assessment result caching.")
    run.add_argument("--refresh", action="store_true", help="Ignore cached results and refresh the cache.")
    run.add_argument(
        "--cache-authenticated",
        action="store_true",
        help="Allow reuse of authenticated results. Disabled by default to avoid stale authorization data.",
    )
    run.set_defaults(func=command_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
