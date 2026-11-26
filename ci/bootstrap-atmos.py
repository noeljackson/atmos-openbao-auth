#!/usr/bin/env python3
"""Bootstrap the pinned Atmos host; Atmos manages every other CLI artifact."""
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    os.umask(0o077)
    lock = json.loads((ROOT / "atmos-bootstrap.lock.json").read_text())
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine().lower()]
    artifact = lock["platforms"][platform.system().lower() + "/" + architecture]
    destination = ROOT / ".tools"
    destination.mkdir(mode=0o700, exist_ok=True)
    target = destination / "atmos"
    if target.is_file() and digest(target) == artifact["sha256"]:
        return
    if not 0 < artifact["size"] <= 512 * 1024 * 1024 or not artifact["url"].startswith("https://github.com/cloudposse/atmos/releases/download/"):
        raise RuntimeError("invalid locked Atmos artifact")
    with tempfile.TemporaryDirectory(prefix="bootstrap-", dir=destination) as directory:
        binary = Path(directory) / "atmos"
        with urllib.request.urlopen(artifact["url"], timeout=60) as source, binary.open("wb") as out:
            remaining = artifact["size"] + 1
            while remaining:
                block = source.read(min(remaining, 1024 * 1024))
                if not block:
                    break
                out.write(block)
                remaining -= len(block)
        if binary.stat().st_size != artifact["size"] or digest(binary) != artifact["sha256"]:
            raise RuntimeError("Atmos artifact checksum/size mismatch")
        binary.chmod(0o755)
        binary.replace(target)
    print("Bootstrapped checksum-verified Atmos " + lock["version"], flush=True)


if __name__ == "__main__":
    main()
