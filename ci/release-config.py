#!/usr/bin/env python3
"""Write native publication configuration containing only credential references."""
import os
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
directory = root / '.atmos/release-config'
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
configuration = {
    'base_path': str(root),
    'settings': {'metrics': {'enabled': False}},
    'toolchain': {
        'install_path': str(root / '.tools/toolchain'),
        'lock_file': str(root / 'toolchain.lock.yaml'),
        'frozen_lock_file': True,
    },
    'auth': {
        'keyring': {'type': 'memory'},
        'identities': {'github-publisher': {
            'kind': 'oci/user',
            'spec': {'registry': 'ghcr.io', 'username': os.environ['GITHUB_ACTOR'], 'password_env': 'GITHUB_TOKEN'},
        }},
    },
    'plugins': {'registries': {'github': {'host': 'ghcr.io', 'identity': 'github-publisher'}}},
}
(directory / 'atmos.yaml').write_text(yaml.safe_dump(configuration))
