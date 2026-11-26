# Project instructions

This repository is the canonical public source for the native Atmos OpenBao
plugin. Keep runtime code independent of private infrastructure and login
daemons; optional session integration follows docs/session-client.md.

Use only synthetic credentials and local endpoints in tests. Never add live
account IDs, infrastructure configuration, tokens or private repository history.

Preserve exact authority checks, session-change fencing when configured,
bounded token custody and fail-closed cleanup. A package build is not a signed
release, anonymous installation or real issuer acceptance.

Run Go race tests/vet and the affected native journeys before delivery. Use the
pinned compiler, Atmos release and module checksums. Keep tests that distinguish
the failure from success; never disable signature checks to make a restore pass.

Publish through the checked-in release workflow from reviewed source. Consumers
pin the actual signer and immutable digest. Follow docs/releases.md on partial
publication; never overwrite an immutable release or silently retry an
uncertain credential operation.

Keep commits signed. Update documentation and examples with contract changes.
