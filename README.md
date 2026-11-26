# Atmos OpenBao authentication

A native Go plugin that exchanges Atmos OIDC credentials for a bounded OpenBao
JWT-auth token. The token is an identity for Atmos's Vault secret store; the
official `secrets/store` and `secrets/env` plugin selects the credentials delivered
to your infrastructure tool.

```text
native OIDC provider → OpenBao identity → Vault store → secrets/env → your tool
```

The OpenBao identity works with any trusted native provider that emits the
`oidc/v1` credential envelope. An optional local session client integrates an
existing workstation login without creating another refresh-token store.

## Capabilities

| Kind | Capability | Purpose |
| --- | --- | --- |
| `noeljackson/openbao` | `auth.identity` | Exchange an OIDC ID token at an explicit JWT-auth mount and manage its lease. |
| `noeljackson/oidc-session` | `auth.provider` | Adapt an optional installed session client to native OIDC credentials and login interactions. |

The provider is optional. Using another native OIDC provider does not require a
session client. Neither capability creates OpenBao roles, policies or secrets.

## Install

Releases are distributed as native OCI plugin packages:

```yaml
plugins:
  packages:
    openbao:
      source: oci://ghcr.io/noeljackson/atmos-openbao-auth
      version: 0.1.0
  policy:
    require_signature: true
    trusted_publishers:
      - publisher: noeljackson
        identity: https://github.com/noeljackson/atmos-openbao-auth/.github/workflows/release.yml@refs/tags/v*
        issuer: https://token.actions.githubusercontent.com
```

Run `atmos plugin install`, inspect the selected release and commit
`.atmos.plugins.lock.yaml`. CI and routine consumers restore that exact digest.
The package must be public before anonymous installation can succeed. Source
availability or a successful upload alone does not establish that a release is
ready; see [release verification](docs/releases.md).

## Configure an OpenBao identity

The following identity assumes `company-login` is an existing native OIDC
provider. All values are examples; the subject, role and policies must match
your server's reviewed configuration.

```yaml
auth:
  keyring:
    type: memory
  identities:
    openbao-reader:
      kind: noeljackson/openbao
      via:
        provider: company-login
      spec:
        address: https://openbao.example.com
        issuer: https://login.example.com
        client_id: infrastructure-cli
        subject: operator-subject
        auth_path: jwt
        role: infrastructure-reader
        expected_policies:
          - infrastructure-reader
          - self-revoke
        self_revoke_policy: self-revoke
        max_ttl_seconds: 120

stores:
  openbao:
    type: hashicorp-vault
    secret: true
    identity: openbao-reader
    options:
      address: https://openbao.example.com
      mount: kv
      identity_lifetime: operation
```

The identity and store addresses must identify the same OpenBao server. Mounts
and roles are explicit; there is no ambient-token or recovery fallback. The
server must issue the exact configured token policy set, no identity policies,
and a non-periodic lease no longer than the configured maximum. `root` and
`default` policies are rejected. Configure the named self-revocation policy on
the server to allow `update` on `auth/token/revoke-self`.

`max_ttl_seconds` is an assertion, not a request for a grant. It must be between
1 and 900. A response with unexpected policies or lifetime is rejected and its
returned token is revoked. OpenBao verifies the JWT; the upstream native OIDC
provider is responsible for verifying its issuer, signature, audience, nonce
and session lifecycle before emitting credentials.

Declare selected document fields using the official `secrets/store` provider,
then map those values through `secrets/env`. Use that environment identity for
the final tool. Explicitly clear inherited `VAULT_TOKEN`, `BAO_TOKEN` and any
inapplicable cloud session token. [The complete example](examples/atmos.yaml)
shows the credential chain and signature policy.

## Existing workstation sessions

An installed client implementing the [session-client protocol](docs/session-client.md)
can supply the optional `noeljackson/oidc-session` provider. Set `session_client`
on the OpenBao identity as well to check that the same ID token and principal
remain active both before and after exchange. Logout, expiry or refresh during
exchange fences delivery and revokes the newly issued token.

The plugin includes this protocol adapter, not a particular login daemon. The
session client owns verification, browser PKCE/device authorization, secure
cross-process persistence, refresh and explicit logout. Refresh tokens never
cross this adapter. Component calls only reuse existing sessions; login is an
explicit native Atmos operation.

## Lifecycle and failure behavior

Use `identity_lifetime: operation` so Atmos releases the store identity before
returning secret values to the command. This release does not log out the OIDC
provider. A failed or unconfirmed revocation blocks dispatch/completion. An
uncertain revocation is marked in private invocation storage and is not retried
automatically.

Issuance is bounded to 30 seconds and cleanup to 10 seconds. Cancellation keeps
custody of a returned token long enough to revoke it. A lost issuance response
cannot prove remote revocation; the server's short maximum TTL is still needed.
The plugin does not print server responses or credentials or store them in
plaintext files. Native plugin execution runs with your operating-system user
privileges, so both the plugin and any configured session client must be trusted.

## Development and compatibility

The initial support matrix is Linux and macOS, amd64 and arm64. The tested host
is Atmos 1.235.0, with operation-scoped Vault identities. Compiler and tool
artifacts are pinned for CI. The SDK is pinned to released Atmos source while
upstream's independently tagged SDK module is unavailable.

```sh
go test -race ./...
go vet ./...
atmos plugin build . --all-platforms
atmos plugin release . --check
```

See [testing](docs/testing.md) for native protocol, secret-store, OpenTofu and
login-presentation journeys. All fixtures are synthetic and use local servers.
These checks do not establish acceptance of a particular organization's real
issuer, daemon or OpenBao role.

Licensed under [Apache-2.0](LICENSE).
