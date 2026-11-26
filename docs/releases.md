# Release process

GitHub is the canonical source for this independent project. A release contains
only this plugin, not the history or configuration of its original consumer.

The release workflow builds a reviewed source commit, runs the authored tests
and native package checks, cross-builds the four supported targets, and uses
native Atmos pack/publish/sign commands. The OCI source annotation identifies
this repository. GitHub's job token publishes the package; GitHub OIDC supplies
the keyless Sigstore signing identity. No long-lived publisher password,
OpenBao credential or workstation login is required.

Before release, inspect the exact staged source, pass the source/secret checks,
and ensure main's required checks pass. Create a signed version tag matching
`metadata.version` in `plugin.yaml`. The workflow must reject a tag outside
reviewed main or a mismatched version.

After publication, retain the immutable index digest, build provenance and
signing result. Verify every platform payload anonymously and qualify a fresh
consumer with the expected workflow certificate identity and issuer. A successful
upload or signature alone does not satisfy anonymous installation acceptance.

GHCR packages initially have private visibility even when their source is
public. GitHub's package settings control this independently. The first
publication may require the owner to make the package public once. Verification
must fail until that setting is confirmed by an anonymous pull; it must not use
the publishing credential to claim public access.

If signing or public verification fails after upload, preserve the reported
digest and inspect the partial state. Do not replace a version with different
bytes. Retry only after changing the failed factor, using the same immutable
release; verification can also be performed independently.

Consumers commit the package declaration, trusted workflow identity and
`.atmos.plugins.lock.yaml`. Roll back by restoring a previously verified
declaration/lock pair. Keep published immutable bytes and signatures while any
consumer references them.
