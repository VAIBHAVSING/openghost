#!/usr/bin/env python3
"""Validate local file references in the published OpenGhost skill."""

from __future__ import annotations

import re
import sys
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILES = [SKILL_ROOT / "SKILL.md", *sorted((SKILL_ROOT / "references").rglob("*.md"))]
ROOT_REFERENCE = re.compile(r"(?<![A-Za-z0-9_./-])((?:references|scripts|assets)/[A-Za-z0-9_./-]+)")
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def clean_target(value: str) -> str:
    return value.strip().strip("`'\"").split("#", 1)[0].rstrip(".,:;)")


def referenced_paths(source: Path, text: str) -> set[Path]:
    paths: set[Path] = set()
    for match in ROOT_REFERENCE.finditer(text):
        target = clean_target(match.group(1))
        if target:
            paths.add(SKILL_ROOT / target)
    for match in MARKDOWN_LINK.finditer(text):
        target = clean_target(match.group(1))
        if not target or "://" in target or target.startswith("#"):
            continue
        paths.add((source.parent / target).resolve())
    return paths


def main() -> int:
    failures: list[str] = []
    skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    frontmatter = skill_text.split("---", 2)
    if len(frontmatter) < 3 or frontmatter[0].strip():
        failures.append("SKILL.md -> missing YAML frontmatter")
    else:
        keys = {
            match.group(1)
            for match in re.finditer(r"(?m)^([a-zA-Z0-9_-]+):", frontmatter[1])
        }
        if keys != {"name", "description"}:
            failures.append(f"SKILL.md -> frontmatter keys must be exactly name and description (found {sorted(keys)})")
        if not re.search(r"(?m)^name:\s*openghost-skill\s*$", frontmatter[1]):
            failures.append("SKILL.md -> name must match the openghost-skill directory")
    for source in SOURCE_FILES:
        text = source.read_text(encoding="utf-8")
        for target in sorted(referenced_paths(source, text)):
            if not target.exists():
                failures.append(f"{source.relative_to(SKILL_ROOT)} -> {target}")
    if failures:
        print("Broken local skill references:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Validated local references in {len(SOURCE_FILES)} skill documents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
