# Testing

Go unit tests cover provider-neutral exchange, explicit authority, URL/mount
confinement, exact policy and lifetime assertions, ambient-token rejection,
session logout/refresh fencing, cancellation custody, failed delivery and
single-attempt revocation. All credentials are synthetic.

`plugin.tests.yaml` runs the race/vet entrypoint through Atmos's native test
runner. Native release checking cross-builds Linux/macOS amd64/arm64, checks
manifest/handler agreement against the actual executable, and validates the OCI
layout. Cross-compilation is not runtime acceptance on the other platform.

`qualification.py` runs the real Atmos host, official signed/locked
`cloudposse/auth-secrets` plugin and OpenTofu against a local fake OpenBao. Its
fixed consumer checks that the reader is revoked before child dispatch and that
no Bao token reaches the child. It scans generated plans, state, variables and
logs for the synthetic credentials. Missing fields, failed revocation,
ambient-token injection, cancellation and a calibrated negative control are
included. Only local `terraform_data` state is created.

`login_qualification.py` runs native login through a PTY with synthetic sessions
and a fake browser opener. It covers browser/device presentation, second-process
reuse, malformed/noninteractive prompts and both cancellation signals. The fake
session is compiled only into the Go test executable; production code cannot
select it.

Run either harness with `--help` for its explicit tool and scratch paths. Use an
owned executable scratch directory; some workstations mount `/tmp` noexec.
Keep diagnostic captures bounded and remove them after reducing the result.
Do not point these tests at real credentials or production endpoints.
