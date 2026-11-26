#!/usr/bin/env python3
"""Install only the reviewed public artifacts from tools.lock.json."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024 * 1024


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def install(name, definition, destination):
    target = destination / name
    receipt = destination / (name + ".json")
    if target.is_file() and receipt.is_file():
        prior = json.loads(receipt.read_text())
        if prior.get("artifact_sha256") == definition["sha256"] and prior.get("binary_sha256") == digest(target):
            return
    if not 0 < definition["size"] <= LIMIT or not definition["url"].startswith("https://github.com/"):
        raise RuntimeError("invalid locked artifact")
    with tempfile.TemporaryDirectory(prefix="install-", dir=destination) as directory:
        scratch = Path(directory)
        archive = scratch / "artifact"
        with urllib.request.urlopen(definition["url"], timeout=60) as source, archive.open("wb") as out:
            remaining = definition["size"] + 1
            while remaining:
                block = source.read(min(remaining, 1024 * 1024))
                if not block:
                    break
                out.write(block)
                remaining -= len(block)
        if archive.stat().st_size != definition["size"] or digest(archive) != definition["sha256"]:
            raise RuntimeError("locked artifact checksum/size mismatch")
        binary = scratch / "binary"
        if definition["format"] == "binary":
            archive.rename(binary)
        elif definition["format"] == "tar.gz":
            with tarfile.open(archive, "r:gz") as bundle:
                member = bundle.getmember(definition["member"])
                if not member.isfile() or not 0 < member.size <= LIMIT:
                    raise RuntimeError("unsafe executable archive member")
                with bundle.extractfile(member) as source, binary.open("wb") as out:
                    shutil.copyfileobj(source, out)
                if binary.stat().st_size != member.size:
                    raise RuntimeError("incomplete executable archive member")
        else:
            raise RuntimeError("unsupported locked artifact format")
        binary.chmod(0o755)
        binary_hash = digest(binary)
        binary.replace(target)
        receipt.write_text(json.dumps({"artifact_sha256": definition["sha256"], "binary_sha256": binary_hash}) + "\n")
    print("Installed checksum-verified " + name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", nargs="+", choices=("atmos", "tofu", "oras", "gitleaks"))
    args = parser.parse_args()
    os.umask(0o077)
    lock = json.loads((ROOT / "tools.lock.json").read_text())
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine().lower()]
    host = platform.system().lower() + "/" + architecture
    destination = ROOT / ".tools"
    destination.mkdir(mode=0o700, exist_ok=True)
    for name in args.tools:
        install(name, lock["tools"][name]["platforms"][host], destination)


if __name__ == "__main__":
    main()
