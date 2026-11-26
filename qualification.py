#!/usr/bin/env python3
"""Exercise a native plugin and Atmos store lifecycle using only synthetic data."""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import zipfile

import yaml

VALUES = {
    "accessKeyId": "synthetic-native-access",
    "secretAccessKey": "synthetic-native-secret",
    "apiToken": "synthetic-native-api",
    "value": "synthetic-legacy-scalar",
}
AMBIENT_TOKENS = {
    "VAULT_TOKEN": "synthetic-inherited-vault",
    "BAO_TOKEN": "synthetic-inherited-bao",
    "AWS_SESSION_TOKEN": "synthetic-inherited-aws-session",
}
FORBIDDEN_VALUES = (*VALUES.values(), *AMBIENT_TOKENS.values(), "synthetic-id", "synthetic-access", "synthetic-bao-")
ROLE = "native-fixture-reader"
POLICIES = [ROLE, "self-revoke"]
MAX_TTL_SECONDS = 120
MODULE = Path(__file__).absolute().parent


class Authority:
    def __init__(self, mode, port=0):
        self.mode, self.lock = mode, threading.Lock()
        self.active, self.events = set(), []
        self.ambient_seen = False
        self.started, self.release = threading.Event(), threading.Event()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(raw)

            def track_ambient(self):
                if self.headers.get("X-Vault-Token") in AMBIENT_TOKENS.values():
                    with owner.lock:
                        owner.ambient_seen = True

            def do_POST(self):
                self.track_ambient()
                if self.path == "/v1/auth/workstation/login":
                    size = int(self.headers.get("Content-Length", "0"))
                    if size > 65536:
                        return self.reply(413, {})
                    body = json.loads(self.rfile.read(size))
                    if body != {"role": ROLE, "jwt": "synthetic-id"}:
                        return self.reply(403, {})
                    if owner.mode == "cancel-auth":
                        owner.started.set()
                        owner.release.wait(15)
                    with owner.lock:
                        token = f"synthetic-bao-{len(owner.events)}"
                        owner.active.add(token)
                        owner.events.append("login")
                    if owner.mode in ("session-logout", "session-refresh"):
                        owner.session_change.write_text("logout" if owner.mode == "session-logout" else "refresh")
                    return self.reply(200, {"auth": {
                        "client_token": token, "policies": POLICIES,
                        "token_policies": POLICIES, "identity_policies": [],
                        "lease_duration": MAX_TTL_SECONDS,
                    }})
                if self.path == "/v1/auth/token/revoke-self":
                    with owner.lock:
                        owner.events.append("revoke")
                        if owner.mode == "revoke-failure":
                            return self.reply(503, {})
                        owner.active.discard(self.headers.get("X-Vault-Token"))
                    return self.reply(204, None)
                self.reply(404, {})

            def do_GET(self):
                self.track_ambient()
                if self.path == "/stats":
                    with owner.lock:
                        return self.reply(200, {"active": len(owner.active)})
                if self.path != "/v1/platform/data/infra/qualification":
                    return self.reply(404, {})
                with owner.lock:
                    if self.headers.get("X-Vault-Token") not in owner.active:
                        return self.reply(403, {})
                    owner.events.append("read")
                if owner.mode == "cancel-read":
                    owner.started.set()
                    owner.release.wait(15)
                values = dict(VALUES)
                if owner.mode == "missing-field":
                    del values["accessKeyId"]
                self.reply(200, {"data": {"data": values, "metadata": {"version": 1}}})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def configure(root, authority, fixture, tofu, plugin_lock, plugin_cache=None, *, clear_ambient=True):
    package = root / "native-package"
    shutil.copytree(MODULE / "schemas", package / "schemas")
    shutil.copyfile(MODULE / "plugin.yaml", package / "plugin.yaml")
    manifest = yaml.safe_load((package / "plugin.yaml").read_text())
    import platform
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
    host = f"{platform.system().lower()}/{arch}"
    executable = package / manifest["spec"]["platforms"][host]["executable"]
    executable.parent.mkdir(parents=True)
    shutil.copyfile(fixture, executable)
    executable.chmod(0o700)
    (executable.parent / ".fixture-backend").write_text(authority.url)
    authority.session_change = executable.parent / ".fixture-session-change"
    metadata = {"issuer": "https://issuer.example.invalid", "client_id": "synthetic-client", "subject": "synthetic-owner"}
    credentials = {name: {"store": "openbao", "path": "infra/qualification", "field": field}
                   for name, field in (("access", "accessKeyId"), ("secret", "secretAccessKey"), ("api", "apiToken"))}
    config = {
        "base_path": str(root), "settings": {"metrics": {"enabled": False}},
        "components": {"terraform": {"command": str(root / "tofu"), "base_path": "components", "auto_generate_backend_file": True}},
        "stacks": {"base_path": "stacks", "included_paths": ["*.yaml"], "name_pattern": "{stage}"},
        "auth": {"keyring": {"type": "memory"}, "providers": {
            "workstation": {"kind": "noeljackson/oidc-session", "spec": dict(metadata, login_method="existing", session_client="/synthetic/session-client")},
            "credentials": {"kind": "secrets/store", "spec": {"credentials": credentials}},
        }, "identities": {
            "openbao": {"kind": "noeljackson/openbao", "via": {"provider": "workstation"}, "spec": dict(metadata, address="https://openbao.example.invalid", auth_path="workstation", role=ROLE, expected_policies=POLICIES, self_revoke_policy="self-revoke", max_ttl_seconds=MAX_TTL_SECONDS, session_client="/synthetic/session-client")},
            "service": {"kind": "secrets/env", "default": True, "via": {"provider": "credentials"}, "spec": {"env": {
                "AWS_ACCESS_KEY_ID": "{{ .credentials.access }}", "AWS_SECRET_ACCESS_KEY": "{{ .credentials.secret }}", "SERVICE_TOKEN": "{{ .credentials.api }}",
            }}},
        }},
        "stores": {"openbao": {"type": "hashicorp-vault", "secret": True, "identity": "openbao", "options": {
            "address": authority.url, "mount": "platform", "identity_lifetime": "operation",
        }}},
        "plugins": {"packages": {
            "own": {"path": str(package), "timeout": "2m"},
            "secrets": {"source": "oci://ghcr.io/cloudposse/atmos/plugins/auth-secrets", "version": "1.1.0"},
        }, "policy": {"require_signature": True, "trusted_publishers": [{
            "publisher": "cloudposse", "identity": "https://github.com/cloudposse/atmos/.github/workflows/plugin-packages.yaml@refs/heads/main", "issuer": "https://token.actions.githubusercontent.com",
        }]}},
    }
    if plugin_cache is not None:
        config["plugins"]["cache_dir"] = str(plugin_cache)
    if clear_ambient:
        config["auth"]["identities"]["service"]["spec"]["env"].update({name: '{{ "" }}' for name in AMBIENT_TOKENS})
    (root / "atmos.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    shutil.copyfile(plugin_lock, root / ".atmos.plugins.lock.yaml")
    (root / "stacks").mkdir()
    (root / "stacks" / "test.yaml").write_text(yaml.safe_dump({"vars": {"stage": "example"}, "components": {"terraform": {"qualification": {"backend_type": "local", "backend": {"local": {"path": "terraform.tfstate"}}, "vars": {"label": "synthetic"}}}}}))
    component = root / "components" / "qualification"
    component.mkdir(parents=True)
    (component / "main.tf").write_text('terraform { required_version = "= 1.13.9" }\nvariable "label" { type = string }\nresource "terraform_data" "proof" { input = var.label }\n')
    wrapper = r'''#!/usr/bin/env python3
import json,os,sys,urllib.request
with urllib.request.urlopen(os.environ["NATIVE_PLUGIN_BACKEND"]+"/stats",timeout=5) as reply:
    active=json.load(reply)["active"]
ambient=any(os.environ.get(name) for name in ("BAO_TOKEN","VAULT_TOKEN","AWS_SESSION_TOKEN"))
def record_child(rejected):
    with open(os.environ["NATIVE_CHILD_RECORD"],"a") as record:
        record.write(json.dumps({"active":active,"args":sys.argv[1:],"ambient_tokens_present":ambient,"guard_rejected":rejected})+"\n")
if active or ambient:
    record_child(True)
    sys.exit(97)
record_child(False)
if not any(flag in sys.argv for flag in ("version","-version","--version")):
    if any(os.environ.get(name)!=value for name,value in {
        "SERVICE_TOKEN":"synthetic-native-api", "AWS_ACCESS_KEY_ID":"synthetic-native-access",
        "AWS_SECRET_ACCESS_KEY":"synthetic-native-secret",
    }.items()):
        sys.exit(98)
    print(os.environ["SERVICE_TOKEN"],flush=True)
os.execv(os.environ["NATIVE_REAL_TOFU"],[os.environ["NATIVE_REAL_TOFU"],*sys.argv[1:]])
'''
    (root / "tofu").write_text(wrapper)
    (root / "tofu").chmod(0o700)
    env = dict(os.environ)
    prefixes = ("ATMOS_", "BAO_", "VAULT_", "AWS_", "HCLOUD_", "TF_VAR_", "OP_SESSION", "CLOUDFLARE_")
    for name in list(env):
        if name.startswith(prefixes):
            del env[name]
    if authority.mode == "ambient-tokens":
        env.update(AMBIENT_TOKENS)
    env.update(ATMOS_CLI_CONFIG_PATH=str(root), ATMOS_BASE_PATH=str(root), ATMOS_TELEMETRY_ENABLED="false",
               NATIVE_PLUGIN_BACKEND=authority.url, NATIVE_CHILD_RECORD=str(root / "children.jsonl"),
               NATIVE_REAL_TOFU=str(tofu), GO_TEST="1")
    return env, component


def run_command(binary, args, root, env, log, authority=None, interrupt=signal.SIGINT):
    with log.open("wb") as output:
        process = subprocess.Popen([str(binary), *args], cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if authority and authority.mode.startswith("cancel-"):
                if not authority.started.wait(30):
                    raise RuntimeError("cancellation checkpoint was not reached")
                process.send_signal(interrupt)
                authority.release.set()
            return process.wait(timeout=90)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def check_artifacts(root):
    for path in root.rglob("*"):
        if path.is_file() and ((".tfstate" in path.name or path.name == "children.jsonl" or path.name.endswith((".tfvars.json", ".log", ".planfile")))):
            raw = path.read_bytes()
            chunks = [raw]
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    chunks.extend(archive.read(name) for name in archive.namelist())
            if any(value.encode() in chunk for value in FORBIDDEN_VALUES for chunk in chunks):
                raise RuntimeError("synthetic credential found in generated artifact or output")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atmos", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--plugin-lock", type=Path, required=True)
    parser.add_argument("--plugin-cache", type=Path, help="Cache populated by a verified native fixture restore")
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--tofu", type=Path, default=Path(shutil.which("tofu") or "/missing"))
    parser.add_argument("--signal", choices=("SIGINT", "SIGTERM"), default="SIGINT")
    parser.add_argument("--port", type=int, default=0, help="Optional fixed loopback port for workstation egress policy")
    parser.add_argument("--case", choices=("success", "ambient-tokens", "missing-field", "revoke-failure", "session-logout", "session-refresh", "cancel-auth", "cancel-read", "all"), default="all")
    parser.add_argument("--negative-control-ambient", action="store_true", help="Omit native blank-token mappings and require the consumer guard to reject synthetic inherited tokens")
    args = parser.parse_args()
    if args.negative_control_ambient and args.case != "ambient-tokens":
        parser.error("the ambient negative control requires --case ambient-tokens")
    for path in (args.atmos, args.fixture, args.tofu):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError("required qualification executable missing")
    cases = ("success", "ambient-tokens", "missing-field", "revoke-failure", "session-logout", "session-refresh", "cancel-auth", "cancel-read") if args.case == "all" else (args.case,)
    for mode in cases:
        authority = Authority(mode, args.port)
        try:
            with tempfile.TemporaryDirectory(prefix=f"native-journey-{mode}.", dir=args.scratch_root) as directory:
                root = Path(directory)
                env, component = configure(root, authority, args.fixture, args.tofu, args.plugin_lock, args.plugin_cache, clear_ambient=not args.negative_control_ambient)
                status = run_command(args.atmos, ["terraform", "plan", "qualification", "-s", "example"], root, env, root / "plan.log", authority, getattr(signal, args.signal))
                children = (root / "children.jsonl").read_text().splitlines() if (root / "children.jsonl").exists() else []
                if args.negative_control_ambient:
                    if status == 0 or len(children) != 1 or not all(json.loads(row)["ambient_tokens_present"] and json.loads(row)["guard_rejected"] for row in children):
                        raise RuntimeError("ambient negative control did not trip the consumer guard")
                elif mode in ("success", "ambient-tokens"):
                    if status or not children:
                        shutil.copyfile(root / "plan.log", args.scratch_root / "native-journey-failure.log")
                        raise RuntimeError(f"native plan failed; structural events={authority.events!r}; private diagnostic retained")
                    if any(json.loads(row)["active"] or json.loads(row)["ambient_tokens_present"] for row in children):
                        raise RuntimeError("child started with an active reader or inherited token")
                    status = run_command(args.atmos, ["terraform", "apply", "qualification", "-s", "example", "-auto-approve"], root, env, root / "apply.log")
                    if status:
                        shutil.copyfile(root / "apply.log", args.scratch_root / "native-journey-failure.log")
                        raise RuntimeError("synthetic local apply failed")
                    states = list(component.rglob("terraform.tfstate"))
                    if not any(any(resource.get("type") == "terraform_data" and resource.get("name") == "proof" for resource in json.loads(state.read_text()).get("resources", [])) for state in states):
                        raise RuntimeError("synthetic state proof missing")
                    children = (root / "children.jsonl").read_text().splitlines()
                elif status == 0 or children:
                    raise RuntimeError("failed or canceled authentication dispatched a child")
                if not args.negative_control_ambient and ("login" not in authority.events or "revoke" not in authority.events):
                    raise RuntimeError("the required issuance/revocation boundary was not observed")
                if mode in ("session-logout", "session-refresh") and (authority.events.count("login") != 1 or authority.events.count("revoke") != 1 or "read" in authority.events):
                    raise RuntimeError("session fencing did not reject the exchange before secret reads")
                if mode != "revoke-failure" and authority.active:
                    raise RuntimeError("OpenBao lease survived command completion")
                if authority.ambient_seen:
                    raise RuntimeError("an inherited token was used to authenticate to the store")
                if any(json.loads(row)["active"] for row in children):
                    raise RuntimeError("an attempted consumer observed an active reader")
                if not args.negative_control_ambient and any(json.loads(row)["ambient_tokens_present"] for row in children):
                    raise RuntimeError("an inherited token reached a consumer")
                check_artifacts(root)
                print(json.dumps({"negative_control": args.negative_control_ambient, "case": mode, "passed": True, "child_calls": len(children), "active_leases": len(authority.active), "signal": args.signal if mode.startswith("cancel-") else None}))
        finally:
            authority.close()


if __name__ == "__main__":
    main()
