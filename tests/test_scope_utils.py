from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "skills" / "openghost-skill" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from scope_utils import validate_scope_file  # noqa: E402


def valid_scope(reviewed: bool = True, port: int = 443) -> str:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=1)).isoformat()
    end = (now + timedelta(hours=1)).isoformat()
    return f"""target_url: https://example.test
authorization:
  reviewed: {str(reviewed).lower()}
  sponsor: security-team
  authorization_document: ticket-123
  test_window: {start}/{end}
  emergency_stop_contact: oncall@example.test
  emergency_stop_phrase: STOP TESTING
  communication_channel: security-test
allowed_hosts:
  - example.test
allowed_ports:
  - {port}
rate_limits:
  requests_per_second: 2
  max_concurrent_requests: 1
active_testing:
  content_discovery: true
data_handling:
  cleanup_required: true
"""


class ScopeValidationTests(unittest.TestCase):
    def validate(self, text: str, **kwargs: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.yaml"
            path.write_text(text, encoding="utf-8")
            return validate_scope_file(path, **kwargs)

    def test_complete_reviewed_scope_passes(self) -> None:
        result = self.validate(valid_scope(), target_url="https://example.test")
        self.assertTrue(result["passed"], result["issues"])

    def test_confirmation_cannot_bypass_unreviewed_scope(self) -> None:
        result = self.validate(valid_scope(reviewed=False), target_url="https://example.test")
        self.assertFalse(result["passed"])
        self.assertIn("authorization.reviewed must be true", result["issues"])

    def test_target_port_and_active_gate_are_enforced(self) -> None:
        result = self.validate(
            valid_scope(port=8443),
            target_url="https://example.test",
            required_gates=["reflected_marker_probes"],
        )
        self.assertFalse(result["passed"])
        self.assertIn("target port is not allowed: 443", result["issues"])
        self.assertIn("active_testing.reflected_marker_probes must be true for this operation", result["issues"])


if __name__ == "__main__":
    unittest.main()
