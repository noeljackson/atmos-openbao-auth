#!/usr/bin/env python3
"""Verify a signed release in two fresh anonymous native Atmos caches."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--digest', required=True)
parser.add_argument('--version', required=True)
args = parser.parse_args()
if len(args.digest) != 71 or not args.digest.startswith('sha256:'):
    raise ValueError('invalid release digest')
int(args.digest[7:], 16)
os.umask(0o077)
env = dict(os.environ)
for key in list(env):
    if key.startswith(('ATMOS_', 'VAULT_', 'BAO_')) or key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GHCR_TOKEN', 'DOCKER_AUTH_CONFIG'):
        env.pop(key)
env.update(ATMOS_TELEMETRY_ENABLED='false', ATMOS_VERSION_CHECK_ENABLED='false')
source = 'oci://ghcr.io/noeljackson/atmos-openbao-auth'
with tempfile.TemporaryDirectory(prefix='anonymous-openbao-') as temporary:
    directory = Path(temporary)
    docker = directory / 'docker'
    docker.mkdir()
    (docker / 'config.json').write_text('{}\n')
    env['DOCKER_CONFIG'] = str(docker)
    config = {
        'base_path': str(directory), 'settings': {'metrics': {'enabled': False}},
        'auth': {'keyring': {'type': 'memory'}},
        'plugins': {
            'cache_dir': str(directory / 'first-cache'),
            'packages': {'openbao': {'source': source, 'version': args.version}},
            'policy': {'require_signature': True, 'trusted_publishers': [{
                'publisher': 'noeljackson',
                'identity': 'https://github.com/noeljackson/atmos-openbao-auth/.github/workflows/release.yml@refs/tags/v' + args.version,
                'issuer': 'https://token.actions.githubusercontent.com',
            }]},
        },
    }
    env.update(ATMOS_CLI_CONFIG_PATH=str(directory), ATMOS_BASE_PATH=str(directory))
    def run(*arguments):
        subprocess.run([str(root / '.tools/atmos'), *arguments], cwd=directory, env=env, check=True, timeout=180)
    path = directory / 'atmos.yaml'
    path.write_text(yaml.safe_dump(config))
    run('plugin', 'verify-public', source, '--reference', args.version, '--digest', args.digest)
    run('plugin', 'install')
    lock = directory / '.atmos.plugins.lock.yaml'
    before = lock.read_bytes()
    parsed = yaml.safe_load(before)
    if args.digest not in str(parsed):
        raise RuntimeError('installed lock did not match published digest')
    config['plugins']['cache_dir'] = str(directory / 'second-cache')
    path.write_text(yaml.safe_dump(config))
    run('plugin', 'install', '--frozen')
    if lock.read_bytes() != before:
        raise RuntimeError('frozen installation changed the release lock')
    output = root / 'dist'
    output.mkdir(exist_ok=True)
    (output / 'consumer.plugins.lock.yaml').write_bytes(before)
    print('Fresh signed anonymous install and frozen restore passed; lock SHA256:', hashlib.sha256(before).hexdigest())
