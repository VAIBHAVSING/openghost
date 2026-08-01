from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "skills" / "openghost-skill" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
SPEC = importlib.util.spec_from_file_location("select_modules", SCRIPT_DIR / "select-modules.py")
assert SPEC and SPEC.loader
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)


class ModuleSelectionTests(unittest.TestCase):
    def test_free_form_notes_do_not_create_input_traits(self) -> None:
        scope = """target_url: https://example.test
allowed_hosts:
  - example.test
active_testing:
  content_discovery: false
notes: Store every file under the local evidence directory.
"""
        relevant = selector.relevant_scope_text(scope).lower()
        self.assertNotIn("file", relevant)
        self.assertNotIn("content discovery", relevant)

    def test_enabled_gate_and_objectives_are_retained(self) -> None:
        scope = """target_url: https://example.test
objectives:
  - Validate GraphQL tenant authorization
active_testing:
  content_discovery: true
"""
        relevant = selector.relevant_scope_text(scope).lower()
        self.assertIn("graphql", relevant)
        self.assertIn("content discovery", relevant)


if __name__ == "__main__":
    unittest.main()
