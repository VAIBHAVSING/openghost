#!/usr/bin/env python3
"""Structured OpenGhost engagement state helper."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
SEVERITIES = {"critical", "high", "medium", "low", "info"}
FINDING_STATUSES = {"confirmed", "likely", "draft", "fixed", "accepted-risk", "false-positive"}
TODO_STATUSES = {"pending", "in-progress", "done", "skip", "cancelled"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
        "traffic",
        "browser",
        "scripts",
        "zap/home",
        "zap/logs",
        "zap/runs",
        "zap/reports",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)
    for name in ["findings.json", "evidence.json", "artifacts.json", "todos.json", "reports.json"]:
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
allowed_hosts:
  - "{args.host}"
exclusions:
  paths:
    - /logout
  hosts: []
rate_limits:
  requests_per_second: 5
notes: "Edit this file before testing. Add every authorized host and exclusion."
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
    if args.status not in FINDING_STATUSES:
        die(f"invalid finding status: {args.status}")
    if args.confidence is not None and not (0 <= args.confidence <= 100):
        die("--confidence must be between 0 and 100")
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
        "cvss": args.cvss or "",
        "owasp": args.owasp or "",
        "cwe": args.cwe or "",
        "wstg_id": args.wstg or "",
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
            f"[{item.get('id', '?')}] {item.get('severity', '?').upper()} "
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


def evidence_lookup(root: Path) -> dict[str, dict[str, Any]]:
    return {item.get("id", ""): item for item in load_records(root, "evidence.json")}


def artifact_lookup(root: Path) -> list[dict[str, Any]]:
    return load_records(root, "artifacts.json")


def finding_sort_key(item: dict[str, Any]) -> tuple[int, str]:
    return (SEVERITY_ORDER.get(item.get("severity", "info"), 5), item.get("id", ""))


def finding_asset_text(finding: dict[str, Any]) -> str:
    asset = finding.get("affected_asset") or {}
    return asset.get("asset") or asset.get("url") or asset.get("path") or "N/A"


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


def report_readiness(findings: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
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
        if missing:
            issues.append(f"{finding.get('id', '?')} missing {', '.join(missing)}")
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
) -> str:
    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    non_confirmed = [item for item in findings if item.get("status") != "confirmed"]
    confirmed.sort(key=finding_sort_key)
    evidence_items = list(evidence.values())
    modules = sorted({item.get("module") for item in findings + todos + evidence_items + artifacts if item.get("module")})
    pending = [item for item in todos if item.get("status") == "pending"]
    readiness_issues = report_readiness(findings)

    lines: list[str] = [
        "# OpenGhost Penetration Test Report",
        "",
        f"**Report ID:** {report_id}",
        f"**Target URL:** {engagement.get('target_url', 'N/A')}",
        f"**Generated:** {generated_at}",
        f"**Store Schema:** v{SCHEMA_VERSION}",
        "",
        "## Executive Summary",
        "",
        f"Confirmed findings: {len(confirmed)}",
        f"Evidence records: {len(evidence_items)}",
        f"Supporting artifacts: {len(artifacts)}",
        f"Open testing items: {len(pending)}",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {severity.title()} | {sum(1 for item in confirmed if item.get('severity') == severity)} |")

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
        lines.append("The following confirmed findings need cleanup before delivery:")
        for issue in readiness_issues:
            lines.append(f"- {issue}")
    else:
        lines.append("All confirmed findings include evidence, reproduction steps, impact, and remediation.")

    lines += [
        "",
        "## Findings Summary",
        "",
        "| ID | Severity | Status | Title | Affected Asset | Evidence |",
        "|---|---|---|---|---|---:|",
    ]
    if confirmed:
        for item in confirmed:
            lines.append(
                f"| {item.get('id', '')} | {item.get('severity', '').title()} | "
                f"{item.get('status', '')} | {item.get('title', '')} | "
                f"{md_cell(finding_asset_text(item))} | {len(item.get('evidence', []))} |"
            )
    else:
        lines.append("| - | - | - | No confirmed findings recorded. | - | 0 |")

    lines += ["", "## Findings", ""]
    if not confirmed:
        lines.append("No confirmed findings recorded.")
        lines.append("")
    for item in confirmed:
        lines += [
            f"### {item.get('id', '?')}: {item.get('title', '')}",
            "",
            f"**Severity:** {item.get('severity', '').upper()}",
            f"**Confidence:** {item.get('confidence', 0)}%",
            f"**Module:** {item.get('module', 'N/A')}",
            f"**Affected Asset:** {finding_asset_text(item)}",
        ]
        if item.get("cvss"):
            lines.append(f"**CVSS:** {item.get('cvss')}")
        mappings = ", ".join(part for part in [item.get("owasp"), item.get("cwe"), item.get("wstg_id")] if part)
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
        if item.get("exploitability"):
            lines += ["#### Exploitability Conditions", "", item.get("exploitability", ""), ""]

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

    lines += ["## Evidence Index", ""]
    if evidence_items:
        lines += ["| ID | Kind | Finding | Module | Title | Path |", "|---|---|---|---|---|---|"]
        for item in evidence_items:
            lines.append(
                f"| {item.get('id', '')} | {md_cell(item.get('kind'))} | {item.get('finding_id', '')} | "
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
    findings = load_records(root, "findings.json")
    todos = load_records(root, "todos.json")
    evidence = evidence_lookup(root)
    artifacts = artifact_lookup(root)
    reports = load_records(root, "reports.json")
    generated_at = utc_now()
    report_id = f"R-{len(reports) + 1:03d}"
    stem = f"report-{timestamp_slug()}"
    md_rel = f"reports/{stem}.md"
    json_rel = f"reports/{stem}.json"
    markdown = render_report_markdown(root, report_id, generated_at, engagement, findings, todos, evidence, artifacts)
    (root / md_rel).write_text(markdown, encoding="utf-8")

    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    pending = [item for item in todos if item.get("status") == "pending"]
    readiness_issues = report_readiness(findings)
    report_json = {
        "schema_version": SCHEMA_VERSION,
        "id": report_id,
        "generated_at": generated_at,
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
        },
        "quality_gate": {
            "passed": not readiness_issues,
            "issues": readiness_issues,
        },
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
    }
    reports.append(record)
    save_records(root, "reports.json", reports)
    append_activity(root, "report.generate", {"id": report_id, "markdown": md_rel, "json": json_rel})
    print(f"report generated: {root / md_rel}")
    print(f"report json generated: {root / json_rel}")
    return 0


def command_report_list(args: argparse.Namespace) -> int:
    root = engagement_dir(args.dir)
    require_v2_engagement(root)
    reports = load_records(root, "reports.json")
    for item in reports:
        print(f"[{item.get('id', '?')}] {item.get('generated_at', '')} {item.get('markdown', '')} {item.get('json', '')}")
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
    evidence_add.set_defaults(func=command_evidence_add)

    evidence_list = sub.add_parser("evidence-list")
    evidence_list.add_argument("--dir", required=True)
    evidence_list.set_defaults(func=command_evidence_list)

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
    finding_add.add_argument("--cvss")
    finding_add.add_argument("--owasp")
    finding_add.add_argument("--cwe")
    finding_add.add_argument("--wstg")
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

    report_generate = sub.add_parser("report-generate")
    report_generate.add_argument("--dir", required=True)
    report_generate.set_defaults(func=command_report_generate)

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
