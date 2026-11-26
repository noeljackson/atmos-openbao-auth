# Official secret-plugin fixture

`auth-secrets.lock.yaml` pins the public official `cloudposse/auth-secrets` 1.1.0
release by immutable OCI index and platform digests. `auth-secrets.sigstore.json`
is public verification material for that exact index, not a token or private
key. Its byte hash, expected publisher, certificate identity and issuer are
recorded in `fixtures.lock.json`.

The fixture preparation downloads the unchanged OCI graph with ORAS, supplies
the pinned public bundle to native `atmos plugin install --frozen --from-layout`,
and keeps signature enforcement enabled. Atmos validates the artifact and
Sigstore evidence against its independent trusted root. No artifact-supplied
root is trusted and no unsigned plugin is executed.

This makes the synthetic journeys reproducible independently of new registry
referrers attached to an old release. Atmos 1.235.0's online collector rejects
a referrer index larger than 32 before selecting signature bundles; the pinned
official index currently reproduces that failure from a fresh cache. This
fixture uses the supported offline restoration path, not a production fallback.
Native online installation of this project's own signed release is a separate
acceptance check. Routine consumer bootstrap must also qualify its dependencies.
