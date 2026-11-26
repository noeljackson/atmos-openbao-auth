# Optional session-client protocol

The local client is an optional integration point for an existing OIDC session
service. The OpenBao identity can consume native `oidc/v1` credentials without
this integration. The client itself is not included in this repository.

Configure `session_client` as an absolute executable path or a path beginning
with `~/`. Home expansion uses the operating system's UID record rather than
an inherited environment variable. The executable must be a regular file owned
by the current UID, executable by its owner and not group/world writable.
Executable symlinks are rejected. The plugin starts it directly without a shell.

The only actions are fixed arguments:

| Action | Meaning |
| --- | --- |
| `atmos-oidc` | Return the currently verified session; never start login. |
| `atmos-login` | Explicit browser login with PKCE or reuse an existing session. |
| `atmos-login-device` | Explicit device authorization or reuse an existing session. |
| `atmos-logout` | Explicitly close the shared OIDC session. |

The client receives a minimal environment and an anonymous output pipe at file
descriptor 3. Standard input is closed; stdout and stderr are discarded. It
emits JSON frames into FD 3, exits successfully and closes the pipe. The whole
response is limited to 128 KiB; unknown fields, duplicate completion or a failed
exit reject the response. The client must stop its login when sent SIGTERM.

A successful session frame has this shape. Values below are deliberately
synthetic and must never be used for authentication:

```json
{
  "done": true,
  "issuer": "https://login.example.com",
  "client_id": "example-cli",
  "subject": "example-operator",
  "credential": "synthetic-id-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "access_token": "synthetic-access-token",
  "access_token_expires_at": "2099-01-01T00:00:00Z"
}
```

The ID token and access token must already be cryptographically verified and
belong to the same session. Refresh tokens stay in the session service. The
issuer, client ID and subject must exactly match the provider configuration.

Explicit login may first send a prompt frame:

```json
{"prompt":{"url":"https://login.example.com/device","code":"ABCD-EFGH","device":true}}
```

Browser prompts have `device: false`, no user code, and an HTTPS authorization
URL. Prompt URLs must share the configured issuer's authority and have no
userinfo or fragment. Device verification URLs must have no query string. The
plugin forwards browser interaction to Atmos's Browser API and device
instructions through Atmos's typed interaction API.

Successful logout emits only `{"done":true}`. To enable exchange fencing, put
the same `session_client`, issuer, client ID and subject on the OpenBao
identity. Its before/after `atmos-oidc` reads must return the exact ID token
received from its upstream provider. A refreshed or closed session fails
closed; the exchange is not repeated.
