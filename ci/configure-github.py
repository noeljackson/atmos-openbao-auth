#!/usr/bin/env python3
"""Apply this project's review and security settings using supported GitHub APIs."""
import json
import subprocess

repository = 'repos/noeljackson/atmos-openbao-auth'


def api(method, path, payload=None):
    arguments = ['gh', 'api', '--method', method, path]
    if payload is not None:
        arguments.extend(['--input', '-'])
    subprocess.run(arguments, input=json.dumps(payload) if payload is not None else None,
                   text=True, stdout=subprocess.DEVNULL, check=True, timeout=30)


api('PATCH', repository, {'delete_branch_on_merge': True, 'allow_squash_merge': True,
                        'allow_merge_commit': False, 'allow_rebase_merge': False})
api('PUT', repository + '/actions/permissions/workflow', {'default_workflow_permissions': 'read',
                                                       'can_approve_pull_request_reviews': False})
api('PUT', repository + '/private-vulnerability-reporting')
api('PUT', repository + '/branches/main/protection', {
    'required_status_checks': {'strict': True, 'contexts': ['required']},
    'enforce_admins': True,
    'required_pull_request_reviews': {'dismiss_stale_reviews': True, 'required_approving_review_count': 0},
    'restrictions': None, 'required_conversation_resolution': True,
    'allow_force_pushes': False, 'allow_deletions': False,
})
api('POST', repository + '/branches/main/protection/required_signatures')
print('Configured required CI, signed commits, review flow, and private vulnerability reporting')
