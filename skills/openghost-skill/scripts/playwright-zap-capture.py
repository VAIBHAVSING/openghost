#!/usr/bin/env python3
"""Capture a Playwright browser visit, optionally through an intercepting proxy."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a browser visit and save evidence artifacts.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--proxy", default="")
    parser.add_argument("--wait-ms", type=int, default=3000)
    parser.add_argument("--headed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    profile = out / "profile"
    profile.mkdir(exist_ok=True)

    console_events: list[dict[str, str]] = []
    failed_requests: list[dict[str, str]] = []
    metadata: dict[str, object] = {
        "url": args.url,
        "proxy": args.proxy,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts": {
            "har": "traffic.har",
            "trace": "trace.zip",
            "screenshot": "screenshot.png",
            "storage_state": "storage-state.json",
            "console": "console.json",
            "failed_requests": "failed-requests.json",
        },
    }

    launch_args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--ignore-certificate-errors",
    ]
    proxy = {"server": args.proxy} if args.proxy else None

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(profile),
            executable_path="/usr/bin/chromium",
            headless=not args.headed,
            args=launch_args,
            proxy=proxy,
            ignore_https_errors=True,
            record_har_path=str(out / "traffic.har"),
            record_har_content="embed",
            viewport={"width": 1440, "height": 1000},
        )
        context.tracing.start(screenshots=True, snapshots=True, sources=True)
        page = context.new_page()
        page.on(
            "console",
            lambda msg: console_events.append(
                {
                    "type": msg.type,
                    "text": msg.text,
                    "location": json.dumps(msg.location),
                }
            ),
        )
        page.on(
            "requestfailed",
            lambda req: failed_requests.append(
                {
                    "url": req.url,
                    "method": req.method,
                    "failure": json.dumps(req.failure),
                }
            ),
        )

        response = page.goto(args.url, wait_until="networkidle", timeout=60000)
        if args.wait_ms > 0:
            time.sleep(args.wait_ms / 1000)
        page.screenshot(path=str(out / "screenshot.png"), full_page=True)
        context.storage_state(path=str(out / "storage-state.json"))
        metadata["final_url"] = page.url
        metadata["status"] = response.status if response is not None else None
        metadata["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        context.tracing.stop(path=str(out / "trace.zip"))
        context.close()

    (out / "console.json").write_text(json.dumps(console_events, indent=2), encoding="utf-8")
    (out / "failed-requests.json").write_text(json.dumps(failed_requests, indent=2), encoding="utf-8")
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps({"browser_artifacts": str(out), "url": args.url, "proxy": args.proxy}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
