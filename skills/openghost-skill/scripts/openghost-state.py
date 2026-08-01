#!/usr/bin/env python3
"""Structured OpenGhost engagement state helper."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import mimetypes
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scope_utils import validate_scope_file


SCHEMA_VERSION = 2
CONTEXT_CACHE_SCHEMA_VERSION = 1
SEVERITIES = {"critical", "high", "medium", "low", "info"}
PRIORITIES = {"P0", "P1", "P2", "P3", "P4"}
FINDING_STATUSES = {"confirmed", "likely", "draft", "fixed", "accepted-risk", "false-positive"}
TODO_STATUSES = {"pending", "in-progress", "done", "skip", "cancelled"}
COVERAGE_STATUSES = {"planned", "in-progress", "tested", "partial", "skipped", "not-applicable"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
NARRATIVE_MERGE_FIELDS = {"summary", "impact", "exploitability", "remediation", "priority_rationale"}

os.umask(0o077)


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


def engagement_dir(path: str) -> Path:
    return Path(path).expanduser().resolve()


def state_dir(root: Path) -> Path:
    return root / "state"


def state_path(root: Path, name: str) -> Path:
    return state_dir(root) / name


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        die(f"invalid JSON in {path}: {exc}")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    tmp.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_activity(root: Path, action: str, payload: dict[str, Any]) -> None:
    entry = {"at": utc_now(), "action": action, **payload}
    path = state_path(root, "activity.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def ensure_layout(root: Path) -> None:
    for rel in [
        "state",
        "notes",
        "evidence",
        "evidence/unlinked",
        "artifacts/inventory",
        "artifacts/auth",
        "artifacts/tools",
        "artifacts/scripts",
        "artifacts/browser",
        "artifacts/packages",
        "reports",
        "runs",
        "cache/context",
        "cache/assessment",
        "traffic",
        "browser",
        "scripts",
        "zap/home",
        "zap/logs",
        "zap/runs",
        "zap/reports",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)
    for name in ["findings.json", "evidence.json", "artifacts.json", "todos.json", "reports.json", "coverage.json"]:
        path = state_path(root, name)
        if not path.exists():
            write_json(path, [])
    activity = state_path(root, "activity.jsonl")
    activity.touch(exist_ok=True)


def require_v2_engagement(root: Path) -> None:
    engagement = read_json(root / "engagement.json", None)
    if not isinstance(engagement, dict) or engagement.get("schema_version") != SCHEMA_VERSION:
        die(f"not a v{SCHEMA_VERSION} engagement: {root}. Run `openghost engagement init --url <url> --name <name>` to create a clean v2 store.")


def next_id(items: list[dict[str, Any]], prefix: str) -> str:
    max_value = 0
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    for item in items:
        match = pattern.match(str(item.get("id", "")))
        if match:
            max_value = max(max_value, int(match.group(1)))
    return f"{prefix}-{max_value + 1:03d}"


def split_refs(values: list[str] | None) -> list[str]:
    refs: list[str] = []
    for value in values or []:
        for part in value.split(","):
            part = part.strip()
            if part and part not in refs:
                refs.append(part)
    return refs


def read_text_if_exists(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def copy_into_store(source: str, root: Path, dest_dir: Path, record_id: str) -> str:
    src = Path(source).expanduser()
    if not src.is_absolute():
        src = (Path.cwd() / src).resolve()
    else:
        src = src.resolve()
    if not src.exists():
        die(f"file not found: {source}")
    if not src.is_file():
        die(f"path is not a regular file: {source}")

    safe_name = slugify(src.stem, "evidence") + src.suffix
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{record_id}-{safe_name}"
    counter = 2
    while dest.exists() and dest.resolve() != src:
        dest = dest_dir / f"{record_id}-{counter}-{safe_name}"
        counter += 1
    if dest.resolve() != src:
        shutil.copy2(src, dest)
    return dest.resolve().relative_to(root).as_posix()


def stored_file_metadata(root: Path, rel_path: str) -> dict[str, Any]:
    path = (root / rel_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        die(f"stored path escapes engagement directory: {rel_path}")
    mime_type, _ = mimetypes.guess_type(path.name)
    return {
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "mime_type": mime_type or "application/octet-stream",
    }


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 2
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    while True:
        candidate = parent / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def attach_evidence_to_finding(root: Path, records: list[dict[str, Any]], evidence_ids: list[str], finding_id: str) -> bool:
    changed = False
    wanted = set(evidence_ids)
    for record in records:
        if record.get("id") not in wanted:
            continue
        existing_finding = record.get("finding_id", "")
        if existing_finding and existing_finding != finding_id:
            continue
        record["finding_id"] = finding_id
        rel_path = record.get("path", "")
        source = root / rel_path
        if source.exists() and source.is_file():
            kind = slugify(record.get("kind", "raw"), "raw")
            destination_dir = root / "evidence" / finding_id / kind
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = unique_path(destination_dir / source.name)
            if source.resolve() != destination.resolve():
                shutil.move(str(source), str(destination))
                record["path"] = destination.resolve().relative_to(root).as_posix()
        changed = True
    return changed


def load_records(root: Path, name: str) -> list[dict[str, Any]]:
    records = read_json(state_path(root, name), [])
    if not isinstance(records, list):
        die(f"state/{name} must contain a JSON array")
    return records


def save_records(root: Path, name: str, records: list[dict[str, Any]]) -> None:
    write_json(state_path(root, name), records)


def command_engagement_init(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    root.mkdir(parents=True, exist_ok=True)
    ensure_layout(root)

    scope = f"""target_url: "{args.url}"
authorization:
  reviewed: false
  sponsor: "TODO"
  authorization_document: "TODO"
  test_window: "TODO"
  emergency_stop_contact: "TODO"
  emergency_stop_phrase: "STOP OPENGHOST TESTING"
  communication_channel: "TODO"
  check_in_cadence: "TODO"
allowed_hosts:
  - "{args.host}"
allowed_ports:
  - 80
  - 443
exclusions:
  paths:
    - /logout
  hosts: []
rate_limits:
  requests_per_second: 5
  max_concurrent_requests: 3
active_testing:
  content_discovery: false
  reflected_marker_probes: false
  zap_active_scan: false
  stateful_api_fuzzing: false
  race_tests: false
  lockout_tests: false
  destructive_tests: false
allowed_write_actions:
  - create_test_record
  - update_own_profile
data_handling:
  allowed_data_access: "test accounts and seeded records only"
  proof_limit: "one redacted sample per finding"
  retention: "store evidence under .openghost only"
  cleanup_required: true
objectives:
  - "Validate authentication and session controls."
  - "Validate tenant and role isolation."
crown_jewels:
  - "user profiles"
  - "invoices"
  - "admin actions"
deconfliction:
  source_ips: []
  user_agent_marker: "openghost-authorized-test"
  test_record_prefix: "openghost-test"
oob_callback: ""
notes: "Edit this file before testing. Add every authorized host, exclusion, communication path, emergency stop contact, data-handling rule, and cleanup expectation."
"""
    (root / "scope.yaml").write_text(scope, encoding="utf-8")

    engagement = {
        "schema_version": SCHEMA_VERSION,
        "name": args.name,
        "target_url": args.url,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "status": "active",
        "store": {
            "findings": "state/findings.json",
            "evidence": "state/evidence.json",
            "artifacts": "state/artifacts.json",
            "todos": "state/todos.json",
            "coverage": "state/coverage.json",
            "reports": "state/reports.json",
            "activity": "state/activity.jsonl",
        },
    }
    write_json(root / "engagement.json", engagement)
    append_activity(root, "engagement.init", {"name": args.name, "target_url": args.url})
    print(f"engagement created: {root}")
    return 0


def command_evidence_add(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    records = load_records(root, "evidence.json")
    eid = next_id(records, "E")
    kind = slugify(args.kind, "raw")
    finding = args.finding or "unlinked"
    rel_path = copy_into_store(args.path, root, root / "evidence" / finding / kind, eid)
    integrity = stored_file_metadata(root, rel_path)
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": eid,
        "title": args.title,
        "kind": args.kind,
        "path": rel_path,
        "finding_id": args.finding or "",
        "module": args.module or "",
        "url": args.url or "",
        "method": args.method or "",
        "role": args.role or "",
        "command": args.command or "",
        "notes": args.notes or "",
        "created_at": utc_now(),
        "captured_at": utc_now(),
        "redaction": args.redaction,
        **integrity,
    }
    records.append(record)
    save_records(root, "evidence.json", records)
    append_activity(root, "evidence.add", {"id": eid, "path": rel_path, "finding_id": record["finding_id"]})
    print(json.dumps({"saved": eid, "path": rel_path, "title": args.title}))
    return 0


def command_evidence_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    records = load_records(root, "evidence.json")
    for item in records:
        linked = f" {item.get('finding_id')}" if item.get("finding_id") else ""
        print(f"[{item.get('id', '?')}] {item.get('kind', '')}{linked} {item.get('title', '')} -> {item.get('path', '')}")
    print(f"Total: {len(records)}")
    return 0


def verify_evidence_records(root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in load_records(root, "evidence.json"):
        rel_path = str(item.get("path") or "")
        path = (root / rel_path).resolve()
        status = "valid"
        detail = ""
        try:
            path.relative_to(root.resolve())
        except ValueError:
            status, detail = "invalid", "path escapes engagement directory"
        if status == "valid" and not path.is_file():
            status, detail = "missing", "stored evidence file is missing"
        expected = str(item.get("sha256") or "")
        actual = ""
        if status == "valid":
            actual = sha256_file(path)
            if not expected:
                status, detail = "unverified", "legacy record has no SHA-256 digest"
            elif actual != expected:
                status, detail = "modified", "SHA-256 digest does not match the registered evidence"
        results.append(
            {
                "id": item.get("id", ""),
                "path": rel_path,
                "status": status,
                "detail": detail,
                "expected_sha256": expected,
                "actual_sha256": actual,
            }
        )
    return results


def command_evidence_verify(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    results = verify_evidence_records(root)
    valid = sum(1 for item in results if item["status"] == "valid")
    if args.json:
        print(json.dumps({"valid": valid, "total": len(results), "results": results}, indent=2))
    else:
        for item in results:
            suffix = f" - {item['detail']}" if item["detail"] else ""
            print(f"[{item['id']}] {item['status']} {item['path']}{suffix}")
        print(f"Valid: {valid}/{len(results)}")
    return 0 if valid == len(results) else 1


def command_artifact_add(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    records = load_records(root, "artifacts.json")
    aid = next_id(records, "A")
    kind = slugify(args.kind, "other")
    rel_path = copy_into_store(args.path, root, root / "artifacts" / kind, aid)
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": aid,
        "title": args.title,
        "kind": args.kind,
        "path": rel_path,
        "finding_id": args.finding or "",
        "module": args.module or "",
        "notes": args.notes or "",
        "created_at": utc_now(),
    }
    records.append(record)
    save_records(root, "artifacts.json", records)
    append_activity(root, "artifact.add", {"id": aid, "path": rel_path, "finding_id": record["finding_id"]})
    print(json.dumps({"saved": aid, "path": rel_path, "title": args.title}))
    return 0


def command_artifact_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    records = load_records(root, "artifacts.json")
    for item in records:
        linked = f" {item.get('finding_id')}" if item.get("finding_id") else ""
        print(f"[{item.get('id', '?')}] {item.get('kind', '')}{linked} {item.get('title', '')} -> {item.get('path', '')}")
    print(f"Total: {len(records)}")
    return 0


def validate_finding(args: argparse.Namespace, evidence_ids: list[str]) -> None:
    if args.severity not in SEVERITIES:
        die("invalid severity: must be critical, high, medium, low, or info")
    if args.priority and args.priority.upper() not in PRIORITIES:
        die("invalid priority: must be P0, P1, P2, P3, or P4")
    if args.status not in FINDING_STATUSES:
        die(f"invalid finding status: {args.status}")
    if args.confidence is not None and not (0 <= args.confidence <= 100):
        die("--confidence must be between 0 and 100")
    if args.cvss and not re.search(r"\bCVSS:(?:4\.0|3\.1)/", args.cvss):
        die("--cvss must include a CVSS:4.0/ or CVSS:3.1/ vector")
    if args.wstg and not args.wstg.startswith("WSTG-v42-"):
        die("--wstg must use a versioned WSTG-v42 identifier")
    if args.asvs and not args.asvs.startswith("ASVS-5.0.0-"):
        die("--asvs must use an ASVS-5.0.0 identifier")
    if args.status == "confirmed":
        missing = []
        if not args.module:
            missing.append("--module")
        if not (args.asset or args.url or args.path):
            missing.append("--asset or --url")
        if args.confidence is None:
            missing.append("--confidence")
        if not args.impact:
            missing.append("--impact")
        if not args.remediation:
            missing.append("--remediation")
        if not args.priority:
            missing.append("--priority")
        if not args.priority_rationale:
            missing.append("--priority-rationale")
        if not evidence_ids:
            missing.append("--evidence")
        if not args.step:
            missing.append("--step")
        if missing:
            die("confirmed finding requires " + ", ".join(missing) + " (use --status draft or --status likely for incomplete leads)")
        if args.confidence < 90:
            die("confirmed finding confidence must be 90 or higher")
        for evidence_id in evidence_ids:
            if not re.match(r"^E-\d{3,}$", evidence_id):
                die(f"confirmed findings must reference registered evidence IDs, not paths: {evidence_id}")


def command_finding_add(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    findings = load_records(root, "findings.json")
    evidence_records = load_records(root, "evidence.json")
    evidence_ids = split_refs(args.evidence)
    validate_finding(args, evidence_ids)

    known_evidence = {item.get("id") for item in evidence_records}
    missing_evidence = [eid for eid in evidence_ids if eid.startswith("E-") and eid not in known_evidence]
    if missing_evidence:
        die("unknown evidence ID(s): " + ", ".join(missing_evidence))

    fid = next_id(findings, "F")
    affected_asset = {
        "asset": args.asset or args.url or args.path or "",
        "url": args.url or "",
        "method": args.method or "",
        "path": args.path or "",
        "parameter": args.parameter or "",
        "role": args.role or "",
        "object": args.object or "",
    }
    finding = {
        "schema_version": SCHEMA_VERSION,
        "id": fid,
        "title": args.title,
        "severity": args.severity,
        "status": args.status,
        "module": args.module or "",
        "confidence": args.confidence if args.confidence is not None else 0,
        "affected_asset": affected_asset,
        "summary": args.summary or "",
        "evidence": evidence_ids,
        "reproduction_steps": [
            {"number": index + 1, "action": step}
            for index, step in enumerate(args.step or [])
        ],
        "impact": args.impact or "",
        "exploitability": args.exploitability or "",
        "remediation": args.remediation or "",
        "priority": args.priority.upper() if args.priority else "",
        "priority_rationale": args.priority_rationale or "",
        "cvss": args.cvss or "",
        "owasp": args.owasp or "",
        "cwe": args.cwe or "",
        "wstg_id": args.wstg or "",
        "asvs": args.asvs or "",
        "references": split_refs(args.reference),
        "notes": args.notes or "",
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    if attach_evidence_to_finding(root, evidence_records, evidence_ids, fid):
        save_records(root, "evidence.json", evidence_records)
    findings.append(finding)
    save_records(root, "findings.json", findings)
    append_activity(root, "finding.add", {"id": fid, "title": args.title, "status": args.status})
    print(json.dumps({"saved": fid, "title": args.title, "severity": args.severity, "status": args.status}))
    return 0


def command_finding_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    findings = load_records(root, "findings.json")
    shown = 0
    for item in findings:
        if args.status and item.get("status") != args.status:
            continue
        shown += 1
        print(
            f"[{item.get('id', '?')}] {item.get('priority') or '-'} {item.get('severity', '?').upper()} "
            f"{item.get('status', '')} {item.get('title', '')}"
        )
    print(f"Total: {shown}/{len(findings)}")
    return 0


def command_todo_add(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    todos = load_records(root, "todos.json")
    tid = next_id(todos, "T")
    todo = {
        "schema_version": SCHEMA_VERSION,
        "id": tid,
        "task": args.task,
        "module": args.module or "",
        "priority": args.priority,
        "status": "pending",
        "finding_id": args.finding or "",
        "evidence": split_refs(args.evidence),
        "notes": args.notes or "",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "completed_at": None,
    }
    todos.append(todo)
    save_records(root, "todos.json", todos)
    append_activity(root, "todo.add", {"id": tid, "task": args.task})
    print(json.dumps({"saved": tid, "task": args.task}))
    return 0


def command_todo_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    todos = load_records(root, "todos.json")
    shown = 0
    for item in todos:
        if args.status and item.get("status") != args.status:
            continue
        shown += 1
        print(f"[{item.get('id', '?')}] {item.get('status', '?')} {item.get('priority', 'medium')} {item.get('task', '')}")
    print(f"Total: {shown}/{len(todos)}")
    return 0


def command_todo_update(args: argparse.Namespace) -> int:
    if args.status not in TODO_STATUSES:
        die("invalid todo status")
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    todos = load_records(root, "todos.json")
    found = None
    for item in todos:
        if item.get("id") == args.id:
            found = item
            break
    if not found:
        die(f"todo not found: {args.id}")
    found["status"] = args.status
    found["updated_at"] = utc_now()
    if args.notes:
        found["notes"] = args.notes
    if args.status in {"done", "skip", "cancelled"}:
        found["completed_at"] = utc_now()
    save_records(root, "todos.json", todos)
    append_activity(root, "todo.update", {"id": args.id, "status": args.status})
    print(json.dumps({"updated": args.id, "status": args.status}))
    return 0


def command_coverage_set(args: argparse.Namespace) -> int:
    if args.status not in COVERAGE_STATUSES:
        die("invalid coverage status")
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    records = load_records(root, "coverage.json")
    record = next((item for item in records if item.get("module") == args.module), None)
    if record is None:
        record = {"schema_version": SCHEMA_VERSION, "module": args.module, "created_at": utc_now()}
        records.append(record)
    record.update(
        {
            "status": args.status,
            "reason": args.reason or "",
            "notes": args.notes or "",
            "updated_at": utc_now(),
        }
    )
    save_records(root, "coverage.json", sorted(records, key=lambda item: str(item.get("module") or "")))
    append_activity(root, "coverage.set", {"module": args.module, "status": args.status})
    print(json.dumps({"module": args.module, "status": args.status}))
    return 0


def command_coverage_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    records = load_records(root, "coverage.json")
    if args.json:
        print(json.dumps(records, indent=2))
    else:
        for item in records:
            reason = f" - {item.get('reason')}" if item.get("reason") else ""
            print(f"[{item.get('status', '?')}] {item.get('module', '')}{reason}")
        print(f"Total: {len(records)}")
    return 0


def latest_assessment_path(root: Path) -> Path | None:
    candidates = sorted(root.glob("runs/assess-*/assessment.json"), reverse=True)
    return candidates[0] if candidates else None


def context_cache_key(root: Path, max_items: int) -> str:
    inputs: dict[str, str | int] = {
        "schema": CONTEXT_CACHE_SCHEMA_VERSION,
        "max_items": max_items,
    }
    for rel in [
        "engagement.json",
        "scope.yaml",
        "state/findings.json",
        "state/evidence.json",
        "state/artifacts.json",
        "state/todos.json",
        "state/coverage.json",
        "state/reports.json",
    ]:
        path = root / rel
        inputs[rel] = sha256_file(path) if path.is_file() else "missing"
    latest = latest_assessment_path(root)
    inputs["latest_assessment"] = sha256_file(latest) if latest else "missing"
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode("utf-8")).hexdigest()


def build_context_summary(root: Path, max_items: int) -> dict[str, Any]:
    engagement = read_json(root / "engagement.json", {})
    findings = load_records(root, "findings.json")
    todos = load_records(root, "todos.json")
    evidence = load_records(root, "evidence.json")
    artifacts = load_records(root, "artifacts.json")
    coverage = load_records(root, "coverage.json")
    reports = load_records(root, "reports.json")
    confirmed = sorted(
        (item for item in findings if item.get("status") == "confirmed"),
        key=finding_sort_key,
    )
    leads = sorted(
        (item for item in findings if item.get("status") in {"likely", "draft"}),
        key=finding_sort_key,
    )
    pending = [item for item in todos if item.get("status") in {"pending", "in-progress"}]
    latest_path = latest_assessment_path(root)
    latest = read_json(latest_path, {}) if latest_path else {}
    scope_status = validate_scope_file(root / "scope.yaml")
    scope_ready = bool(scope_status["passed"])
    integrity = verify_evidence_records(root)
    invalid_evidence = [item for item in integrity if item["status"] != "valid"]
    recommendations: list[str] = []
    if not scope_ready:
        recommendations.append("Complete and explicitly approve scope.yaml before active testing.")
    if leads:
        recommendations.append("Validate the highest-severity likely findings; do not report them as confirmed yet.")
    if pending:
        recommendations.append("Resolve or disposition the highest-priority open testing items.")
    if invalid_evidence:
        recommendations.append("Repair or explain evidence-integrity failures before report delivery.")
    if not coverage:
        recommendations.append("Record module coverage so report limitations are explicit.")
    if not recommendations:
        recommendations.append("Generate and validate the delivery report.")

    def brief_finding(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": item.get("id"),
            "severity": item.get("severity"),
            "priority": item.get("priority"),
            "title": item.get("title"),
            "asset": finding_asset_text(item),
        }

    return {
        "schema_version": CONTEXT_CACHE_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "engagement": {
            "name": engagement.get("name"),
            "target_url": engagement.get("target_url"),
            "status": engagement.get("status"),
            "scope_ready": scope_ready,
            "scope_issues": scope_status["issues"],
        },
        "counts": {
            "confirmed_findings": len(confirmed),
            "likely_or_draft_findings": len(leads),
            "open_todos": len(pending),
            "evidence_records": len(evidence),
            "supporting_artifacts": len(artifacts),
            "invalid_evidence": len(invalid_evidence),
            "coverage_modules": len(coverage),
            "reports": len(reports),
        },
        "top_confirmed": [brief_finding(item) for item in confirmed[:max_items]],
        "top_leads": [brief_finding(item) for item in leads[:max_items]],
        "open_todos": [
            {key: item.get(key) for key in ["id", "priority", "module", "task", "status"]}
            for item in pending[:max_items]
        ],
        "coverage": [
            {key: item.get(key) for key in ["module", "status", "reason"]}
            for item in coverage
        ],
        "latest_assessment": {
            "status": latest.get("status"),
            "generated_at": latest.get("generated_at"),
            "mode": latest.get("mode"),
            "cache": latest.get("cache") or {},
            "errors": len(latest.get("errors") or []),
        }
        if latest
        else None,
        "latest_report": (
            {key: reports[-1].get(key) for key in ["id", "delivery_status", "quality_gate_passed", "generated_at", "markdown"]}
            if reports
            else None
        ),
        "recommended_next_actions": recommendations[:max_items],
        "usage": "Use this compact snapshot first. Load raw state or evidence only for the active hypothesis.",
    }


def render_context_markdown(summary: dict[str, Any]) -> str:
    engagement = summary["engagement"]
    counts = summary["counts"]
    lines = [
        "# OpenGhost engagement context",
        "",
        f"Target: {engagement.get('target_url') or 'N/A'}",
        f"Scope ready: {'yes' if engagement.get('scope_ready') else 'no'}",
        (
            "State: "
            f"{counts['confirmed_findings']} confirmed, "
            f"{counts['likely_or_draft_findings']} leads, "
            f"{counts['open_todos']} open todos, "
            f"{counts['evidence_records']} evidence records"
        ),
        "",
    ]
    if not engagement.get("scope_ready"):
        lines += ["## Scope blockers", ""]
        lines.extend(f"- {issue}" for issue in (engagement.get("scope_issues") or [])[:5])
        lines.append("")
    for heading, key in [("Confirmed findings", "top_confirmed"), ("Leads to validate", "top_leads")]:
        items = summary[key]
        if items:
            lines += [f"## {heading}", ""]
            for item in items:
                priority = f" {item.get('priority')}" if item.get("priority") else ""
                lines.append(f"- {item.get('id')} {str(item.get('severity') or '').upper()}{priority}: {item.get('title')}")
            lines.append("")
    if summary["open_todos"]:
        lines += ["## Open work", ""]
        for item in summary["open_todos"]:
            lines.append(f"- {item.get('id')} [{item.get('priority')}]: {item.get('task')}")
        lines.append("")
    if summary["coverage"]:
        lines += ["## Coverage", ""]
        for item in summary["coverage"]:
            lines.append(f"- {item.get('module')}: {item.get('status')}")
        lines.append("")
    latest = summary.get("latest_assessment")
    if latest:
        cache = latest.get("cache") or {}
        lines += [
            "## Latest assessment",
            "",
            f"- Status: {latest.get('status') or 'unknown'}",
            f"- Mode: {latest.get('mode') or 'unknown'}",
            f"- Cache: {cache.get('hits', 0)} hit(s), {cache.get('misses', 0)} miss(es)",
            f"- Errors: {latest.get('errors', 0)}",
            "",
        ]
    latest_report = summary.get("latest_report")
    if latest_report:
        lines += [
            "## Latest report",
            "",
            f"- ID: {latest_report.get('id')}",
            f"- Status: {latest_report.get('delivery_status') or 'legacy'}",
            f"- Quality gate: {'passed' if latest_report.get('quality_gate_passed') else 'not passed or legacy'}",
            f"- Path: {latest_report.get('markdown')}",
            "",
        ]
    lines += ["## Next actions", ""]
    lines.extend(f"- {item}" for item in summary["recommended_next_actions"])
    lines += ["", summary["usage"], ""]
    return "\n".join(lines)


def command_context_show(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    key = context_cache_key(root, args.max_items)
    cache_dir = root / "cache" / "context"
    json_path = cache_dir / f"{key}.json"
    markdown_path = cache_dir / f"{key}.md"
    cache_age_seconds = (
        max(0, int(datetime.now(timezone.utc).timestamp() - json_path.stat().st_mtime))
        if json_path.is_file()
        else 0
    )
    cache_hit = json_path.is_file() and markdown_path.is_file() and cache_age_seconds <= 300 and not args.refresh
    if cache_hit:
        summary = read_json(json_path, {})
    else:
        summary = build_context_summary(root, args.max_items)
        summary["cache"] = {"key": key, "source": "local engagement state"}
        write_json(json_path, summary)
        markdown_path.write_text(render_context_markdown(summary), encoding="utf-8")
    summary["cache_hit"] = cache_hit
    summary["cache_age_seconds"] = cache_age_seconds if cache_hit else 0
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(markdown_path.read_text(encoding="utf-8"), end="")
        print(f"context_cache: {'hit' if cache_hit else 'miss'}")
    return 0


def command_cache_status(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    engagement_cache_root = root / "cache"
    shared_cache_root = Path(args.state_root).expanduser().resolve() / "cache" if args.state_root else engagement_cache_root
    groups: dict[str, dict[str, int]] = {}
    for name in ["scripts", "assessment", "context"]:
        directory = shared_cache_root / name if name == "scripts" else engagement_cache_root / name
        files = [path for path in directory.rglob("*") if path.is_file()] if directory.exists() else []
        groups[name] = {
            "files": len(files),
            "bytes": sum(path.stat().st_size for path in files),
        }
    result = {
        "cache_roots": {
            "shared_scripts": str(shared_cache_root / "scripts"),
            "engagement": str(engagement_cache_root),
        },
        "groups": groups,
        "total_files": sum(item["files"] for item in groups.values()),
        "total_bytes": sum(item["bytes"] for item in groups.values()),
        "note": "All caches are local generated engagement data; no OpenGhost service is involved.",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"shared script cache: {shared_cache_root / 'scripts'}")
        print(f"engagement cache: {engagement_cache_root}")
        for name, item in groups.items():
            print(f"- {name}: {item['files']} file(s), {item['bytes']} byte(s)")
        print(f"total: {result['total_files']} file(s), {result['total_bytes']} byte(s)")
    return 0


def evidence_lookup(root: Path) -> dict[str, dict[str, Any]]:
    return {item.get("id", ""): item for item in load_records(root, "evidence.json")}


def artifact_lookup(root: Path) -> list[dict[str, Any]]:
    return load_records(root, "artifacts.json")


def finding_sort_key(item: dict[str, Any]) -> tuple[int, str]:
    return (SEVERITY_ORDER.get(item.get("severity", "info"), 5), item.get("id", ""))


def finding_asset_text(finding: dict[str, Any]) -> str:
    asset = finding.get("affected_asset") or {}
    return asset.get("asset") or asset.get("url") or asset.get("path") or "N/A"


def normalize_report_value(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def canonical_asset_value(value: Any) -> str:
    text = normalize_report_value(value)
    if text not in {"", "/"}:
        text = text.rstrip("/")
    return text


def finding_duplicate_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str, str, str, str]:
    asset = finding.get("affected_asset") or {}
    effective_asset = asset.get("asset") or asset.get("url") or asset.get("path") or ""
    return (
        normalize_report_value(finding.get("title")),
        normalize_report_value(finding.get("module")),
        normalize_report_value(finding.get("status")),
        canonical_asset_value(effective_asset),
        normalize_report_value(asset.get("method")).upper(),
        canonical_asset_value(asset.get("parameter")),
        canonical_asset_value(asset.get("role")),
        canonical_asset_value(asset.get("object")),
    )


def unique_values(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def priority_rank(value: Any) -> int:
    return PRIORITY_ORDER.get(str(value or "").upper(), 99)


def highest_severity(left: Any, right: Any) -> str:
    left_value = str(left or "info").lower()
    right_value = str(right or "info").lower()
    return left_value if SEVERITY_ORDER.get(left_value, 99) <= SEVERITY_ORDER.get(right_value, 99) else right_value


def highest_priority(left: Any, right: Any) -> str:
    left_value = str(left or "").upper()
    right_value = str(right or "").upper()
    return left_value if priority_rank(left_value) <= priority_rank(right_value) else right_value


def step_action(step: Any) -> str:
    if isinstance(step, dict):
        return str(step.get("action") or "").strip()
    return str(step or "").strip()


def merge_reproduction_steps(left: list[Any], right: list[Any]) -> list[dict[str, Any]]:
    actions: list[str] = []
    seen: set[str] = set()
    for step in [*(left or []), *(right or [])]:
        action = step_action(step)
        key = normalize_report_value(action)
        if not action or key in seen:
            continue
        seen.add(key)
        actions.append(action)
    return [{"number": index + 1, "action": action} for index, action in enumerate(actions)]


def append_merged_note(finding: dict[str, Any], duplicate_id: str, field: str, value: Any) -> None:
    text = str(value or "").strip()
    if not text:
        return
    existing = str(finding.get("notes") or "")
    if normalize_report_value(text) and normalize_report_value(text) in normalize_report_value(existing):
        return
    label = field.replace("_", " ")
    addition = f"Merged duplicate {duplicate_id} {label}: {text}"
    finding["notes"] = "\n\n".join(part for part in [existing, addition] if part)


def append_merged_field_detail(finding: dict[str, Any], duplicate_id: str, field: str, value: Any) -> None:
    text = str(value or "").strip()
    if not text:
        return
    existing = str(finding.get(field) or "").strip()
    if normalize_report_value(text) and normalize_report_value(text) in normalize_report_value(existing):
        return
    addition = f"Additional detail from merged duplicate {duplicate_id}: {text}"
    finding[field] = "\n\n".join(part for part in [existing, addition] if part)


def merge_duplicate_finding(primary: dict[str, Any], duplicate: dict[str, Any]) -> None:
    duplicate_id = str(duplicate.get("id") or "unknown")
    merged_ids = primary.setdefault("merged_duplicate_ids", [])
    if duplicate_id not in merged_ids:
        merged_ids.append(duplicate_id)

    primary["severity"] = highest_severity(primary.get("severity"), duplicate.get("severity"))
    primary["priority"] = highest_priority(primary.get("priority"), duplicate.get("priority"))
    primary["confidence"] = max(int(primary.get("confidence") or 0), int(duplicate.get("confidence") or 0))
    primary["evidence"] = unique_values([*(primary.get("evidence") or []), *(duplicate.get("evidence") or [])])
    primary["references"] = unique_values([*(primary.get("references") or []), *(duplicate.get("references") or [])])
    primary["reproduction_steps"] = merge_reproduction_steps(
        primary.get("reproduction_steps") or [],
        duplicate.get("reproduction_steps") or [],
    )

    primary_asset = primary.setdefault("affected_asset", {})
    duplicate_asset = duplicate.get("affected_asset") or {}
    for field in ["asset", "url", "method", "path", "parameter", "role", "object"]:
        if not primary_asset.get(field) and duplicate_asset.get(field):
            primary_asset[field] = duplicate_asset.get(field)

    for field in [
        "summary",
        "impact",
        "exploitability",
        "remediation",
        "priority_rationale",
        "cvss",
        "owasp",
        "cwe",
        "wstg_id",
        "asvs",
    ]:
        primary_value = primary.get(field)
        duplicate_value = duplicate.get(field)
        if not primary_value and duplicate_value:
            primary[field] = duplicate_value
        elif duplicate_value and normalize_report_value(primary_value) != normalize_report_value(duplicate_value):
            if field in NARRATIVE_MERGE_FIELDS:
                append_merged_field_detail(primary, duplicate_id, field, duplicate_value)
            else:
                append_merged_note(primary, duplicate_id, field, duplicate_value)

    append_merged_note(primary, duplicate_id, "notes", duplicate.get("notes"))


def deduplicate_findings_for_report(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str, str, str, str, str, str], dict[str, Any]] = {}
    groups_by_primary: dict[str, dict[str, Any]] = {}

    for finding in findings:
        key = finding_duplicate_key(finding)
        if key not in by_key:
            report_finding = copy.deepcopy(finding)
            by_key[key] = report_finding
            deduped.append(report_finding)
            continue

        primary = by_key[key]
        primary_id = str(primary.get("id") or "unknown")
        duplicate_id = str(finding.get("id") or "unknown")
        merge_duplicate_finding(primary, finding)
        group = groups_by_primary.setdefault(
            primary_id,
            {
                "primary_id": primary_id,
                "merged_ids": [],
                "title": primary.get("title", ""),
                "module": primary.get("module", ""),
                "status": primary.get("status", ""),
                "affected_asset": finding_asset_text(primary),
            },
        )
        if duplicate_id not in group["merged_ids"]:
            group["merged_ids"].append(duplicate_id)

    merged_groups = list(groups_by_primary.values())
    return deduped, {
        "raw_finding_count": len(findings),
        "reported_finding_count": len(deduped),
        "exact_duplicate_group_count": len(merged_groups),
        "merged_finding_count": sum(len(group["merged_ids"]) for group in merged_groups),
        "exact_duplicate_groups": merged_groups,
    }


def md_cell(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", "<br>")


def scope_excerpt(root: Path) -> str:
    text = read_text_if_exists(root / "scope.yaml").strip()
    if not text:
        return "No scope file was found."
    max_chars = 3000
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "\n# ... truncated; see scope.yaml"
    return text


def report_readiness(
    root: Path,
    findings: list[dict[str, Any]],
    todos: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    coverage: list[dict[str, Any]],
) -> list[str]:
    issues: list[str] = []
    scope_result = validate_scope_file(root / "scope.yaml", enforce_window=False)
    issues.extend(f"scope: {issue}" for issue in scope_result["issues"])
    integrity_by_id = {item["id"]: item for item in verify_evidence_records(root)}
    for evidence_id, integrity in integrity_by_id.items():
        if integrity.get("status") != "valid":
            issues.append(f"evidence {evidence_id} integrity is {integrity.get('status', 'unknown')}")
    for finding in findings:
        if finding.get("status") != "confirmed":
            continue
        missing = []
        if not finding.get("evidence"):
            missing.append("evidence")
        if not finding.get("reproduction_steps"):
            missing.append("reproduction steps")
        if not finding.get("impact"):
            missing.append("impact")
        if not finding.get("remediation"):
            missing.append("remediation")
        if not finding.get("priority"):
            missing.append("priority")
        if not finding.get("priority_rationale"):
            missing.append("priority rationale")
        if missing:
            issues.append(f"{finding.get('id', '?')} missing {', '.join(missing)}")
        cvss = str(finding.get("cvss") or "")
        if cvss and not re.search(r"\bCVSS:(?:4\.0|3\.1)/", cvss):
            issues.append(f"{finding.get('id', '?')} CVSS must include a v4.0 or v3.1 vector")
        wstg = str(finding.get("wstg_id") or "")
        if wstg and not wstg.startswith("WSTG-v42-"):
            issues.append(f"{finding.get('id', '?')} WSTG mapping must use a versioned WSTG-v42 identifier")
        asvs = str(finding.get("asvs") or "")
        if asvs and not asvs.startswith("ASVS-5.0.0-"):
            issues.append(f"{finding.get('id', '?')} ASVS mapping must use an ASVS-5.0.0 identifier")
        for evidence_id in finding.get("evidence") or []:
            if evidence_id not in evidence:
                issues.append(f"{finding.get('id', '?')} references unknown evidence {evidence_id}")
                continue
    if not coverage:
        issues.append("no assessment-module coverage has been recorded")
    for item in coverage:
        if item.get("status") in {"planned", "in-progress", "partial"}:
            issues.append(f"coverage for {item.get('module', '?')} is {item.get('status')}")
        if item.get("status") in {"skipped", "not-applicable"} and not item.get("reason"):
            issues.append(f"coverage for {item.get('module', '?')} requires a reason")
    for item in todos:
        if item.get("status") in {"pending", "in-progress"} and str(item.get("priority") or "").lower() in {
            "critical",
            "high",
            "p0",
            "p1",
        }:
            issues.append(f"high-priority testing item {item.get('id', '?')} is still {item.get('status')}")
    return issues


def render_report_markdown(
    root: Path,
    report_id: str,
    generated_at: str,
    engagement: dict[str, Any],
    findings: list[dict[str, Any]],
    todos: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    artifacts: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    readiness_issues: list[str],
    delivery_status: str,
    deduplication: dict[str, Any] | None = None,
) -> str:
    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    non_confirmed = [item for item in findings if item.get("status") != "confirmed"]
    confirmed.sort(key=finding_sort_key)
    evidence_items = list(evidence.values())
    modules = sorted({item.get("module") for item in findings + todos + evidence_items + artifacts if item.get("module")})
    pending = [item for item in todos if item.get("status") == "pending"]
    integrity_results = verify_evidence_records(root)
    valid_evidence = sum(1 for item in integrity_results if item.get("status") == "valid")

    lines: list[str] = [
        "# OpenGhost Penetration Test Report",
        "",
        f"**Report ID:** {report_id}",
        f"**Target URL:** {engagement.get('target_url', 'N/A')}",
        f"**Generated:** {generated_at}",
        f"**Store Schema:** v{SCHEMA_VERSION}",
        f"**Delivery Status:** {delivery_status}",
        "",
        "## Executive Summary",
        "",
        (
            "This report separates evidence-backed confirmed findings from unvalidated leads. "
            "Coverage and outstanding work below define what was and was not assessed."
        ),
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Confirmed findings | {len(confirmed)} |",
        f"| Leads/drafts excluded from confirmed risk | {len(non_confirmed)} |",
        f"| Integrity-valid evidence | {valid_evidence}/{len(evidence_items)} |",
        f"| Supporting artifacts | {len(artifacts)} |",
        f"| Open testing items | {len(pending)} |",
        f"| Modules with recorded coverage | {len(coverage)} |",
        "",
        "### Confirmed risk by severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {severity.title()} | {sum(1 for item in confirmed if item.get('severity') == severity)} |")

    prioritized = [item for item in confirmed if item.get("priority")]
    if prioritized:
        lines += ["", "Top remediation priorities:"]
        for item in sorted(prioritized, key=lambda value: (value.get("priority", "P9"), finding_sort_key(value)))[:5]:
            lines.append(f"- {item.get('priority')}: {item.get('id', '?')} - {item.get('title', '')}")

    lines += [
        "",
        "## Scope and Limitations",
        "",
        "The active scope file at generation time was:",
        "",
        "```yaml",
        scope_excerpt(root),
        "```",
        "",
        "## Methodology",
        "",
        (
            "OpenGhost uses an authorization-first, hypothesis-led workflow: establish scope and test gates, "
            "inventory the authenticated surface, validate abuse cases with bounded requests, preserve evidence, "
            "and record explicit coverage and limitations. Automated signals remain leads until manually validated."
        ),
        "",
    ]
    if modules:
        lines.append("Modules with recorded work: " + ", ".join(modules))
    else:
        lines.append("No module-specific work was recorded.")
    lines += [
        "",
        f"Recorded proof files: {len(evidence_items)}",
        f"Recorded support artifacts: {len(artifacts)}",
        f"Recorded todos: {len(todos)}",
        "",
        "## Report Quality Gate",
        "",
    ]
    if readiness_issues:
        lines.append("The following scope, coverage, evidence, or finding issues block final delivery:")
        for issue in readiness_issues:
            lines.append(f"- {issue}")
    else:
        lines.append("PASSED: scope, coverage, evidence integrity, and confirmed-finding completeness are delivery-ready.")
    duplicate_groups = (deduplication or {}).get("exact_duplicate_groups", [])
    if duplicate_groups:
        lines += ["", "Exact duplicate findings merged for this report:"]
        for group in duplicate_groups:
            lines.append(f"- {group.get('primary_id')}: merged {', '.join(group.get('merged_ids', []))}")

    lines += [
        "",
        "## Findings Summary",
        "",
        "| ID | Priority | Severity | Status | Title | Affected Asset | Evidence |",
        "|---|---|---|---|---|---|---:|",
    ]
    if confirmed:
        for item in confirmed:
            lines.append(
                f"| {item.get('id', '')} | {item.get('priority') or '-'} | "
                f"{item.get('severity', '').title()} | "
                f"{item.get('status', '')} | {item.get('title', '')} | "
                f"{md_cell(finding_asset_text(item))} | {len(item.get('evidence', []))} |"
            )
    else:
        lines.append("| - | - | - | - | No confirmed findings recorded. | - | 0 |")

    lines += ["", "## Assessment Coverage", ""]
    if coverage:
        lines += ["| Module | Status | Reason / limitation |", "|---|---|---|"]
        for item in coverage:
            lines.append(
                f"| {md_cell(item.get('module'))} | {md_cell(item.get('status'))} | "
                f"{md_cell(item.get('reason') or item.get('notes'))} |"
            )
    else:
        lines.append("No module coverage was recorded. This report must be treated as incomplete.")

    lines += ["", "## Findings", ""]
    if not confirmed:
        lines.append("No confirmed findings recorded.")
        lines.append("")
    for item in confirmed:
        lines += [
            f"### {item.get('id', '?')}: {item.get('title', '')}",
            "",
            f"**Severity:** {item.get('severity', '').upper()}",
            f"**Priority:** {item.get('priority') or 'Not recorded'}",
            f"**Confidence:** {item.get('confidence', 0)}%",
            f"**Module:** {item.get('module', 'N/A')}",
            f"**Affected Asset:** {finding_asset_text(item)}",
        ]
        if item.get("merged_duplicate_ids"):
            lines.append(f"**Merged Duplicate Records:** {', '.join(item.get('merged_duplicate_ids', []))}")
        if item.get("cvss"):
            lines.append(f"**CVSS:** {item.get('cvss')}")
        mappings = ", ".join(
            part for part in [item.get("owasp"), item.get("cwe"), item.get("wstg_id"), item.get("asvs")] if part
        )
        if mappings:
            lines.append(f"**Mappings:** {mappings}")
        asset = item.get("affected_asset") or {}
        lines += [
            "",
            "#### Affected Component",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| URL | {md_cell(asset.get('url'))} |",
            f"| Method | {md_cell(asset.get('method'))} |",
            f"| Path | {md_cell(asset.get('path'))} |",
            f"| Parameter | {md_cell(asset.get('parameter'))} |",
            f"| Role/Context | {md_cell(asset.get('role'))} |",
            f"| Object | {md_cell(asset.get('object'))} |",
        ]
        if item.get("summary"):
            lines += ["", "#### Summary", "", item.get("summary", "")]
        lines += ["", "#### Evidence", ""]
        refs = item.get("evidence", [])
        if refs:
            lines += ["| ID | Kind | Title | Path | Command/Context |", "|---|---|---|---|---|"]
            for ref in refs:
                ev = evidence.get(ref, {})
                context = ev.get("command") or " ".join(part for part in [ev.get("method"), ev.get("url"), ev.get("role")] if part)
                lines.append(
                    f"| {ref} | {md_cell(ev.get('kind'))} | {md_cell(ev.get('title'))} | "
                    f"`{ev.get('path', ref)}` | {md_cell(context)} |"
                )
        else:
            lines.append("No evidence linked.")
        lines += ["", "#### Reproduction Steps", ""]
        steps = item.get("reproduction_steps") or []
        if steps:
            for step in steps:
                lines.append(f"{step.get('number', 0)}. {step.get('action', '')}")
        else:
            lines.append("No reproduction steps recorded.")
        lines += [
            "",
            "#### Impact",
            "",
            item.get("impact") or "Not recorded.",
            "",
            "#### Remediation",
            "",
            item.get("remediation") or "Not recorded.",
            "",
        ]
        if item.get("priority_rationale"):
            lines += ["#### Priority Rationale", "", item.get("priority_rationale", ""), ""]
        if item.get("exploitability"):
            lines += ["#### Exploitability Conditions", "", item.get("exploitability", ""), ""]

    lines += ["## Remediation Roadmap", ""]
    if confirmed:
        lines += ["| Priority | Finding | Module | Recommended action |", "|---|---|---|---|"]
        for item in sorted(confirmed, key=lambda value: (priority_rank(value.get("priority")), finding_sort_key(value))):
            lines.append(
                f"| {item.get('priority') or '-'} | {item.get('id', '?')}: {md_cell(item.get('title'))} | "
                f"{md_cell(item.get('module'))} | {md_cell(item.get('remediation'))} |"
            )
    else:
        lines.append("No confirmed-finding remediation actions were recorded.")
    lines.append("")

    if non_confirmed:
        lines += ["## Leads and Draft Findings", ""]
        for item in sorted(non_confirmed, key=finding_sort_key):
            lines.append(f"- [{item.get('id', '?')}] {item.get('status', '')} {item.get('severity', '').upper()}: {item.get('title', '')}")
        lines.append("")

    if pending:
        lines += ["## Outstanding Testing Items", ""]
        for item in pending:
            lines.append(f"- [{item.get('id', '?')}] {item.get('task', '')} ({item.get('module', '')})")
        lines.append("")

    lines += ["## Evidence Integrity Index", ""]
    if evidence_items:
        integrity_by_id = {item["id"]: item for item in integrity_results}
        lines += ["| ID | Integrity | Redaction | Kind | Finding | Module | Title | Path |", "|---|---|---|---|---|---|---|---|"]
        for item in evidence_items:
            lines.append(
                f"| {item.get('id', '')} | {integrity_by_id.get(item.get('id'), {}).get('status', 'unknown')} | "
                f"{item.get('redaction', 'legacy')} | {md_cell(item.get('kind'))} | {item.get('finding_id', '')} | "
                f"{md_cell(item.get('module'))} | {md_cell(item.get('title'))} | `{item.get('path', '')}` |"
            )
    else:
        lines.append("No evidence records.")

    lines += ["", "## Appendix", ""]
    if artifacts:
        lines += ["| Artifact ID | Kind | Module | Title | Path |", "|---|---|---|---|---|"]
        for item in artifacts:
            lines.append(
                f"| {item.get('id', '')} | {md_cell(item.get('kind'))} | {md_cell(item.get('module'))} | "
                f"{md_cell(item.get('title'))} | `{item.get('path', '')}` |"
            )
    else:
        lines.append("No artifact records.")
    return "\n".join(lines) + "\n"


def command_report_generate(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    engagement = read_json(root / "engagement.json", {})
    raw_findings = load_records(root, "findings.json")
    findings, deduplication = deduplicate_findings_for_report(raw_findings)
    todos = load_records(root, "todos.json")
    evidence = evidence_lookup(root)
    artifacts = artifact_lookup(root)
    coverage = load_records(root, "coverage.json")
    reports = load_records(root, "reports.json")
    readiness_issues = report_readiness(root, findings, todos, evidence, coverage)
    if readiness_issues and not args.allow_incomplete:
        details = "\n".join(f"- {issue}" for issue in readiness_issues)
        die(
            "report quality gate failed; resolve the following items or generate an explicit draft "
            f"with --allow-incomplete:\n{details}"
        )
    delivery_status = "DRAFT - INCOMPLETE" if readiness_issues else "FINAL - QUALITY GATE PASSED"
    generated_at = utc_now()
    report_id = f"R-{len(reports) + 1:03d}"
    stem = f"report-{timestamp_slug()}"
    md_rel = f"reports/{stem}.md"
    json_rel = f"reports/{stem}.json"
    markdown = render_report_markdown(
        root,
        report_id,
        generated_at,
        engagement,
        findings,
        todos,
        evidence,
        artifacts,
        coverage,
        readiness_issues,
        delivery_status,
        deduplication,
    )
    (root / md_rel).write_text(markdown, encoding="utf-8")

    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    pending = [item for item in todos if item.get("status") == "pending"]
    integrity_results = verify_evidence_records(root)
    report_json = {
        "schema_version": SCHEMA_VERSION,
        "id": report_id,
        "generated_at": generated_at,
        "delivery_status": delivery_status,
        "engagement": engagement,
        "summary": {
            "confirmed_findings": len(confirmed),
            "draft_or_likely_findings": len(findings) - len(confirmed),
            "evidence_records": len(evidence),
            "supporting_artifacts": len(artifacts),
            "open_testing_items": len(pending),
            "by_severity": {
                severity: sum(1 for item in confirmed if item.get("severity") == severity)
                for severity in ["critical", "high", "medium", "low", "info"]
            },
            "by_priority": {
                priority: sum(1 for item in confirmed if item.get("priority") == priority)
                for priority in ["P0", "P1", "P2", "P3", "P4"]
            },
        },
        "quality_gate": {
            "passed": not readiness_issues,
            "issues": readiness_issues,
        },
        "deduplication": deduplication,
        "coverage": coverage,
        "evidence_integrity": integrity_results,
        "findings": findings,
        "evidence": list(evidence.values()),
        "artifacts": artifacts,
        "todos": todos,
        "paths": {"markdown": md_rel, "json": json_rel},
    }
    write_json(root / json_rel, report_json)
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": report_id,
        "generated_at": generated_at,
        "markdown": md_rel,
        "json": json_rel,
        "confirmed_findings": len(confirmed),
        "delivery_status": delivery_status,
        "quality_gate_passed": not readiness_issues,
    }
    reports.append(record)
    save_records(root, "reports.json", reports)
    append_activity(root, "report.generate", {"id": report_id, "markdown": md_rel, "json": json_rel})
    print(f"delivery status: {delivery_status}")
    print(f"report generated: {root / md_rel}")
    print(f"report json generated: {root / json_rel}")
    return 0


def command_report_validate(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    ensure_layout(root)
    raw_findings = load_records(root, "findings.json")
    findings, _ = deduplicate_findings_for_report(raw_findings)
    todos = load_records(root, "todos.json")
    evidence = evidence_lookup(root)
    coverage = load_records(root, "coverage.json")
    issues = report_readiness(root, findings, todos, evidence, coverage)
    result = {"passed": not issues, "issues": issues}
    if args.json:
        print(json.dumps(result, indent=2))
    elif issues:
        print("Report quality gate: FAILED")
        for issue in issues:
            print(f"- {issue}")
    else:
        print("Report quality gate: PASSED")
    return 0 if not issues else 1


def command_report_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    reports = load_records(root, "reports.json")
    for item in reports:
        print(
            f"[{item.get('id', '?')}] {item.get('delivery_status', 'legacy')} "
            f"{item.get('generated_at', '')} {item.get('markdown', '')} {item.get('json', '')}"
        )
    print(f"Total: {len(reports)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenGhost structured engagement state helper")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("engagement-init")
    init.add_argument("--dir", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--url", required=True)
    init.add_argument("--host", required=True)
    init.set_defaults(func=command_engagement_init)

    evidence_add = sub.add_parser("evidence-add")
    evidence_add.add_argument("--dir", required=True)
    evidence_add.add_argument("--path", required=True)
    evidence_add.add_argument("--kind", required=True)
    evidence_add.add_argument("--title", required=True)
    evidence_add.add_argument("--finding")
    evidence_add.add_argument("--module")
    evidence_add.add_argument("--url")
    evidence_add.add_argument("--method")
    evidence_add.add_argument("--role")
    evidence_add.add_argument("--command")
    evidence_add.add_argument("--notes")
    evidence_add.add_argument("--redaction", choices=["raw", "redacted", "sanitized"], default="raw")
    evidence_add.set_defaults(func=command_evidence_add)

    evidence_list = sub.add_parser("evidence-list")
    evidence_list.add_argument("--dir", required=True)
    evidence_list.set_defaults(func=command_evidence_list)

    evidence_verify = sub.add_parser("evidence-verify")
    evidence_verify.add_argument("--dir", required=True)
    evidence_verify.add_argument("--json", action="store_true")
    evidence_verify.set_defaults(func=command_evidence_verify)

    artifact_add = sub.add_parser("artifact-add")
    artifact_add.add_argument("--dir", required=True)
    artifact_add.add_argument("--path", required=True)
    artifact_add.add_argument("--kind", required=True)
    artifact_add.add_argument("--title", required=True)
    artifact_add.add_argument("--finding")
    artifact_add.add_argument("--module")
    artifact_add.add_argument("--notes")
    artifact_add.set_defaults(func=command_artifact_add)

    artifact_list = sub.add_parser("artifact-list")
    artifact_list.add_argument("--dir", required=True)
    artifact_list.set_defaults(func=command_artifact_list)

    finding_add = sub.add_parser("finding-add")
    finding_add.add_argument("--dir", required=True)
    finding_add.add_argument("--title", required=True)
    finding_add.add_argument("--severity", required=True)
    finding_add.add_argument("--status", default="confirmed")
    finding_add.add_argument("--module")
    finding_add.add_argument("--asset")
    finding_add.add_argument("--url")
    finding_add.add_argument("--method")
    finding_add.add_argument("--path")
    finding_add.add_argument("--parameter")
    finding_add.add_argument("--role")
    finding_add.add_argument("--object")
    finding_add.add_argument("--confidence", type=int)
    finding_add.add_argument("--summary")
    finding_add.add_argument("--evidence", action="append")
    finding_add.add_argument("--step", action="append")
    finding_add.add_argument("--impact")
    finding_add.add_argument("--exploitability")
    finding_add.add_argument("--remediation")
    finding_add.add_argument("--priority")
    finding_add.add_argument("--priority-rationale", dest="priority_rationale")
    finding_add.add_argument("--cvss")
    finding_add.add_argument("--owasp")
    finding_add.add_argument("--cwe")
    finding_add.add_argument("--wstg")
    finding_add.add_argument("--asvs")
    finding_add.add_argument("--reference", action="append")
    finding_add.add_argument("--notes")
    finding_add.set_defaults(func=command_finding_add)

    finding_list = sub.add_parser("finding-list")
    finding_list.add_argument("--dir", required=True)
    finding_list.add_argument("--status")
    finding_list.set_defaults(func=command_finding_list)

    todo_add = sub.add_parser("todo-add")
    todo_add.add_argument("--dir", required=True)
    todo_add.add_argument("--task", required=True)
    todo_add.add_argument("--module")
    todo_add.add_argument("--priority", default="medium")
    todo_add.add_argument("--finding")
    todo_add.add_argument("--evidence", action="append")
    todo_add.add_argument("--notes")
    todo_add.set_defaults(func=command_todo_add)

    todo_list = sub.add_parser("todo-list")
    todo_list.add_argument("--dir", required=True)
    todo_list.add_argument("--status")
    todo_list.set_defaults(func=command_todo_list)

    todo_update = sub.add_parser("todo-update")
    todo_update.add_argument("--dir", required=True)
    todo_update.add_argument("--id", required=True)
    todo_update.add_argument("--status", required=True)
    todo_update.add_argument("--notes")
    todo_update.set_defaults(func=command_todo_update)

    coverage_set = sub.add_parser("coverage-set")
    coverage_set.add_argument("--dir", required=True)
    coverage_set.add_argument("--module", required=True)
    coverage_set.add_argument("--status", required=True)
    coverage_set.add_argument("--reason")
    coverage_set.add_argument("--notes")
    coverage_set.set_defaults(func=command_coverage_set)

    coverage_list = sub.add_parser("coverage-list")
    coverage_list.add_argument("--dir", required=True)
    coverage_list.add_argument("--json", action="store_true")
    coverage_list.set_defaults(func=command_coverage_list)

    context_show = sub.add_parser("context-show")
    context_show.add_argument("--dir", required=True)
    context_show.add_argument("--json", action="store_true")
    context_show.add_argument("--refresh", action="store_true")
    context_show.add_argument("--max-items", type=int, default=5)
    context_show.set_defaults(func=command_context_show)

    cache_status = sub.add_parser("cache-status")
    cache_status.add_argument("--dir", required=True)
    cache_status.add_argument("--state-root")
    cache_status.add_argument("--json", action="store_true")
    cache_status.set_defaults(func=command_cache_status)

    report_generate = sub.add_parser("report-generate")
    report_generate.add_argument("--dir", required=True)
    report_generate.add_argument("--allow-incomplete", action="store_true")
    report_generate.set_defaults(func=command_report_generate)

    report_validate = sub.add_parser("report-validate")
    report_validate.add_argument("--dir", required=True)
    report_validate.add_argument("--json", action="store_true")
    report_validate.set_defaults(func=command_report_validate)

    report_list = sub.add_parser("report-list")
    report_list.add_argument("--dir", required=True)
    report_list.set_defaults(func=command_report_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
