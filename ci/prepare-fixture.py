#!/usr/bin/env python3
"""Restore a pinned official plugin fixture through native signature verification."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.umask(0o077)
    spec = json.loads((ROOT / "testdata/fixtures.lock.json").read_text())
    signature = ROOT / "testdata" / spec["signature_file"]
    if hashlib.sha256(signature.read_bytes()).hexdigest() != spec["signature_sha256"]:
        raise RuntimeError("fixture signature pin mismatch")
    directory = ROOT / ".atmos/fixtures"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = dict(os.environ)
    for name in list(env):
        if name.startswith(("ATMOS_", "VAULT_", "BAO_", "AWS_", "HCLOUD_", "TF_VAR_")) or name in ("GH_TOKEN", "GITHUB_TOKEN", "GHCR_TOKEN"):
            env.pop(name)
    docker = directory / "anonymous-registry"
    docker.mkdir(mode=0o700, exist_ok=True)
    (docker / "config.json").write_text("{}\n")
    env["DOCKER_CONFIG"] = str(docker)
    layout = directory / "official-layout"
    if not layout.exists():
        subprocess.run([str(ROOT / ".tools/oras"), "cp", "--to-oci-layout", spec["source"], str(layout) + ":fixture"], env=env, check=True, timeout=180)
    # ORAS exposes both the root index and its platform manifests as layout
    # roots. Atmos's offline reader expects exactly the unchanged release index.
    index_path = layout / "index.json"
    outer = json.loads(index_path.read_text())
    roots = [entry for entry in outer["manifests"] if entry["digest"] == spec["index_digest"]]
    if len(roots) != 1 or roots[0]["mediaType"] != "application/vnd.oci.image.index.v1+json":
        raise RuntimeError("fixture layout root mismatch")
    content = layout / "blobs/sha256" / spec["index_digest"].split(":")[1]
    if hashlib.sha256(content.read_bytes()).hexdigest() != spec["index_digest"].split(":")[1]:
        raise RuntimeError("fixture release index mismatch")
    outer["manifests"] = roots
    index_path.write_text(json.dumps(outer) + "\n")
    shutil.copyfile(signature, layout / "signature.sigstore.json")
    configuration = {
        "base_path": str(directory),
        "settings": {"metrics": {"enabled": False}},
        "auth": {"keyring": {"type": "memory"}},
        "plugins": {
            "cache_dir": str(directory / "cache"),
            "packages": {"secrets": {"source": "oci://ghcr.io/cloudposse/atmos/plugins/auth-secrets", "version": "1.1.0"}},
            "policy": {"require_signature": True, "trusted_publishers": [{key: spec[key] for key in ("publisher", "identity", "issuer")}]},
        },
    }
    (directory / "atmos.yaml").write_text(yaml.safe_dump(configuration))
    shutil.copyfile(ROOT / "testdata/auth-secrets.lock.yaml", directory / ".atmos.plugins.lock.yaml")
    env.update(ATMOS_CLI_CONFIG_PATH=str(directory), ATMOS_BASE_PATH=str(directory), ATMOS_TELEMETRY_ENABLED="false", ATMOS_VERSION_CHECK_ENABLED="false")
    subprocess.run([str(ROOT / ".tools/atmos"), "plugin", "install", "--frozen", "--from-layout", str(layout)], cwd=directory, env=env, check=True, timeout=180)


if __name__ == "__main__":
    main()
