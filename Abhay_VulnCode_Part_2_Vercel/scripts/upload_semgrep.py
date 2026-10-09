from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/upload_semgrep.py semgrep.json", file=sys.stderr)
        return 2

    if not os.getenv("VULNCODE_API_URL") or not os.getenv("VULNCODE_INGEST_TOKEN"):
        print("VulnCode upload skipped because API configuration is unavailable.")
        return 0

    semgrep = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    payload = {
        "repository_full_name": required_env("GITHUB_REPOSITORY"),
        "commit_sha": required_env("GITHUB_SHA"),
        "ref": os.getenv("GITHUB_REF"),
        "installation_id": (
            int(os.environ["VULNCODE_INSTALLATION_ID"])
            if os.getenv("VULNCODE_INSTALLATION_ID")
            else None
        ),
        "semgrep": semgrep,
    }
    request = urllib.request.Request(
        required_env("VULNCODE_API_URL").rstrip("/") + "/api/v1/ingest/semgrep",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {required_env('VULNCODE_INGEST_TOKEN')}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        print(error.read().decode("utf-8"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
