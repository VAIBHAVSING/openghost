from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "skills" / "openghost-skill" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
SPEC = importlib.util.spec_from_file_location("openghost_state", SCRIPT_DIR / "openghost-state.py")
assert SPEC and SPEC.loader
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)


def complete_scope() -> str:
    now = datetime.now(timezone.utc)
    return f"""target_url: https://example.test
authorization:
  reviewed: true
  sponsor: security-team
  authorization_document: ticket-123
  test_window: {(now - timedelta(hours=1)).isoformat()}/{(now + timedelta(hours=1)).isoformat()}
  emergency_stop_contact: oncall@example.test
  emergency_stop_phrase: STOP TESTING
  communication_channel: security-test
allowed_hosts:
  - example.test
allowed_ports:
  - 443
rate_limits:
  requests_per_second: 2
  max_concurrent_requests: 1
active_testing:
  content_discovery: false
data_handling:
  cleanup_required: true
"""


class StateHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "engagement"
        self.root.mkdir()
        state.ensure_layout(self.root)
        state.write_json(
            self.root / "engagement.json",
            {
                "schema_version": state.SCHEMA_VERSION,
                "name": "test",
                "target_url": "https://example.test",
                "status": "active",
            },
        )
        (self.root / "scope.yaml").write_text(complete_scope(), encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_context_key_changes_when_state_changes(self) -> None:
        first = state.context_cache_key(self.root, 5)
        state.write_json(
            self.root / "state" / "todos.json",
            [{"id": "T-001", "status": "pending", "priority": "medium", "task": "Validate a lead"}],
        )
        second = state.context_cache_key(self.root, 5)
        self.assertNotEqual(first, second)

    def test_evidence_digest_detects_modification(self) -> None:
        source = Path(self.tempdir.name) / "response.txt"
        source.write_text("redacted response", encoding="utf-8")
        state.command_evidence_add(
            Namespace(
                dir=str(self.root),
                path=str(source),
                kind="response",
                title="Response",
                finding=None,
                module="access-control",
                url="/api/object/1",
                method="GET",
                role="user-a",
                command=None,
                notes=None,
                redaction="redacted",
            )
        )
        records = state.load_records(self.root, "evidence.json")
        self.assertEqual("valid", state.verify_evidence_records(self.root)[0]["status"])
        (self.root / records[0]["path"]).write_text("changed", encoding="utf-8")
        self.assertEqual("modified", state.verify_evidence_records(self.root)[0]["status"])

    def test_final_report_requires_closed_coverage(self) -> None:
        with self.assertRaises(SystemExit):
            state.command_report_generate(Namespace(dir=str(self.root), allow_incomplete=False))
        state.write_json(
            self.root / "state" / "coverage.json",
            [{"module": "surface-map", "status": "tested", "reason": "", "notes": ""}],
        )
        self.assertEqual(0, state.command_report_generate(Namespace(dir=str(self.root), allow_incomplete=False)))
        report = json.loads(next((self.root / "reports").glob("*.json")).read_text(encoding="utf-8"))
        self.assertEqual("FINAL - QUALITY GATE PASSED", report["delivery_status"])


if __name__ == "__main__":
    unittest.main()
