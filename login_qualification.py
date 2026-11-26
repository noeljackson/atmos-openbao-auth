#!/usr/bin/env python3
"""Qualify native login presentation with a PTY and synthetic session only."""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import pty
import select
import shutil
import signal
import subprocess
import tempfile
import time

import yaml

MODULE = Path(__file__).absolute().parent
CODE = b"ABCD-EFGH"
DEVICE_URI = b"https://issuer.example.invalid/device"
PRIVATE = (b"synthetic-id", b"synthetic-access", b"synthetic-private-", b"synthetic-state")


def configure(root, fixture, mode):
    package = root / "package"
    package.mkdir()
    shutil.copytree(MODULE / "schemas", package / "schemas")
    shutil.copyfile(MODULE / "plugin.yaml", package / "plugin.yaml")
    manifest = yaml.safe_load((package / "plugin.yaml").read_text())
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    executable = package / manifest["spec"]["platforms"][f"{platform.system().lower()}/{arch}"]["executable"]
    executable.parent.mkdir(parents=True)
    shutil.copyfile(fixture, executable)
    executable.chmod(0o700)
    (executable.parent / ".fixture-backend").write_text("http://127.0.0.1:1")
    (executable.parent / ".fixture-mode").write_text(mode)
    config = {
        "base_path": str(root), "settings": {"metrics": {"enabled": False}},
        "auth": {"keyring": {"type": "memory"}, "providers": {"workstation": {
            "kind": "noeljackson/oidc-session", "spec": {
                "issuer": "https://issuer.example.invalid", "client_id": "synthetic-client",
                "subject": "synthetic-owner", "login_method": "browser" if mode == "browser" else "device",
                "session_client": "/synthetic/session-client",
            },
        }}},
        "plugins": {"packages": {"own": {"path": str(package), "timeout": "15s"}}},
    }
    (root / "atmos.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    fakebin = root / "fakebin"
    fakebin.mkdir()
    opener = '#!/usr/bin/python3\nimport json,os,sys\nwith open(os.environ["NATIVE_BROWSER_RECORD"],"w") as out:\n    json.dump(sys.argv[1:],out)\n'
    for name in ("xdg-open", "open"):
        (fakebin / name).write_text(opener)
        (fakebin / name).chmod(0o700)
    # A whitelist prevents workstation credentials, ambient config and CI flags
    # from changing this synthetic interactive/noninteractive qualification.
    env = {
        "PATH": str(fakebin) + ":/usr/bin:/bin", "HOME": str(root),
        "XDG_CONFIG_HOME": str(root / "config"), "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_DATA_HOME": str(root / "data"), "TERM": "xterm", "NO_COLOR": "1",
        "ATMOS_CLI_CONFIG_PATH": str(root), "ATMOS_BASE_PATH": str(root),
        "ATMOS_TELEMETRY_ENABLED": "false", "ATMOS_INTERACTIVE": "true",
        "NATIVE_BROWSER_RECORD": str(root / "browser.json"),
    }
    return env, executable.parent / ".fixture-approved"


def login(binary, root, env, name, terminal=True, interrupt=None):
    master, slave = pty.openpty() if terminal else (None, None)
    captured = bytearray()
    with (root / f"{name}.stdout.log").open("wb") as stdout, (root / f"{name}.stderr.log").open("wb") as stderr:
        process = subprocess.Popen(
            [str(binary), "auth", "login", "--provider", "workstation"], cwd=root, env=env,
            stdin=slave if terminal else subprocess.DEVNULL,
            stderr=slave if terminal else stderr, stdout=stdout, start_new_session=True,
        )
        if terminal:
            os.close(slave)
        sent = False
        deadline = time.monotonic() + 35
        try:
            while time.monotonic() < deadline:
                chunk = b""
                ready = select.select([master], [], [], 0.05)[0] if terminal else []
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        chunk = b""
                    if chunk:
                        captured.extend(chunk)
                        stderr.write(chunk)
                        stderr.flush()
                        if len(captured) > 1024 * 1024:
                            raise RuntimeError("native UI output exceeded bound")
                if interrupt and CODE in captured and not sent:
                    process.send_signal(interrupt)
                    sent = True
                if process.poll() is not None and not chunk:
                    break
            else:
                raise RuntimeError("native login exceeded bounded qualification time")
            status = process.wait(timeout=3)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            if terminal:
                os.close(master)
    out, err = (root / f"{name}.stdout.log").read_bytes(), (root / f"{name}.stderr.log").read_bytes()
    if any(value in out + err for value in PRIVATE):
        raise RuntimeError("private synthetic auth material reached stdout/stderr")
    if CODE in out or DEVICE_URI in out:
        raise RuntimeError("device prompt reached stdout")
    if interrupt and not sent:
        raise RuntimeError("device cancellation checkpoint was not reached")
    return status, out, err


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atmos", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--expect-missing-device-prompt", action="store_true", help="Verify the released-host presentation defect")
    args = parser.parse_args()
    for path in (args.atmos, args.fixture):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError("required qualification executable missing")
    os.umask(0o077)
    cases = ("device",) if args.expect_missing_device_prompt else ("device", "browser", "noninteractive", "device-query", "device-extra", "SIGINT", "SIGTERM")
    for case in cases:
        with tempfile.TemporaryDirectory(prefix=f"native-login-{case}.", dir=args.scratch_root) as directory:
            root = Path(directory)
            mode = "device-cancel" if case in ("SIGINT", "SIGTERM") else "device" if case == "noninteractive" else case
            env, approval = configure(root, args.fixture, mode)
            try:
                status, _, err = login(args.atmos, root, env, "first", terminal=case != "noninteractive", interrupt=getattr(signal, case) if case.startswith("SIG") else None)
                if args.expect_missing_device_prompt:
                    if status or CODE in err:
                        raise RuntimeError("released host did not reproduce the expected invisible device prompt")
                elif case in ("device", "browser"):
                    if status or not approval.exists():
                        raise RuntimeError("synthetic explicit login failed")
                    if case == "device" and (CODE not in err or DEVICE_URI not in err):
                        raise RuntimeError("public device instructions were not shown on stderr")
                    if case == "browser":
                        record = root / "browser.json"
                        deadline = time.monotonic() + 3
                        while not record.exists() and time.monotonic() < deadline:
                            time.sleep(0.02)
                        if not record.exists() or json.loads(record.read_text()) != ["https://issuer.example.invalid/oauth/v2/authorize?state=synthetic-state"]:
                            raise RuntimeError("host Browser API did not open the synthetic authorization URL")
                    reused, _, second = login(args.atmos, root, env, "reuse")
                    if reused or CODE in second:
                        raise RuntimeError("second process did not reuse the synthetic session without approval")
                elif not status:
                    raise RuntimeError("rejected or canceled login unexpectedly succeeded")
                if case in ("noninteractive", "SIGINT", "SIGTERM") and approval.exists():
                    raise RuntimeError("approval completed on a noninteractive or canceled path")
                if case in ("noninteractive", "device-query", "device-extra") and CODE in err:
                    raise RuntimeError("invalid or noninteractive prompt was rendered")
            except Exception:
                for capture in root.glob("*.log"):
                    shutil.copyfile(capture, args.scratch_root / f"native-login-failure-{capture.name}")
                raise
            outcome = "released host reproduces missing device prompt" if args.expect_missing_device_prompt else "synthetic native login presentation and output boundaries"
            print(f"PASS {case}: {outcome}", flush=True)


if __name__ == "__main__":
    main()
