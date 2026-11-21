# Athena TestLab

A standalone, offline-first integration-test harness for rAthena and other legacy game servers. It performs real, bounded OS-level observations and produces reviewable evidence.

Independent of [RO Doctor](https://github.com/webimario85-svg/ro-doctor) and ValkiRO. Community project, not affiliated with Gravity or rAthena maintainers.

## Core capabilities (v0.1.0 and v0.2.0)

- tcp-open: connect to an explicit IPv4/IPv6 loopback port and observe acceptance.
- tcp-exchange: send up to 256 explicit bytes to a loopback socket, compare returned bytes. Not a Ragexe protocol handshake.
- process-exit: launch an existing workspace-relative executable only with --allow-exec and shell=False. Record timeout, exit code and SHA-256 of at most 2 MiB of output, never raw output.
- rathena-login (v0.2.0): send a genuine rAthena 0x0064 login request only to authorized loopback with --allow-login-probe, then classify modern/legacy refusals or acceptance headers. A correct refusal proves a packet exchange, never a successful game login.
- Optional OpenSSH Ed25519 evidence attestation: sign and verify the SHA-256 inventory of sanitized report artifacts against an explicitly trusted public key. Signature validity does not prove a test outcome.
- Strict manifest schema, up to 64 tests per suite and bounded timeouts.
- Local run.json and sanitized JSONL session.log. Optional case artifacts with actual client/server binary SHA-256 and verifiable log digest, compatible with RO Doctor case v1.
- Built-in TCP probes are loopback-only. Explicitly authorized subprocesses may have their own networking and must be externally isolated. No built-in database connections, game asset distribution, GitHub Actions or implicit background execution.

## Install

Python 3.10+; no third-party runtime dependencies:

    python -m pip install -e .

Or run with PYTHONPATH=src and python -m athenatestlab.

## Example

See [docs/suite.example.json](docs/suite.example.json) and [suite schema](docs/suite.schema.json). The example has a port probe and a map-server --run-once invocation, based on upstream rAthena guidance. Nothing is executed by merely reading the example.

    athena-testlab list-kinds

    athena-testlab run --manifest docs/suite.example.json --workspace /path/to/rathena --output /tmp/testlab-run-001 --allow-exec

A login port check will fail if no listener is running; a process test will fail if map-server was not built. Those are real observations, never synthetic successes.

For RO Doctor integration, additionally specify --client-exe and --server-exe paths relative to the workspace. See the [interoperability guide](docs/ro-doctor-contract.md). RO Doctor independently checks hashes and log bytes.

## M6: genuine protocol response and repeatable isolated lab

The new [protocol and signed-evidence guide](docs/m6-protocol-and-evidence.md) documents the 55-byte CA_LOGIN packet, strict opt-in, tests of missing-account refusal, signed reports and the reproducible Docker/MySQL lab script. The official rAthena login-server returned a real 0x083e/error 0 rejection to a disposable missing account (1 PASS / 0 FAIL). The full lab was repeated through the checked-in PowerShell script with automatic teardown. Positive account authentication and a real Ragexe EXE were **not** tested.

Use OpenSSH ssh-keygen (optional; not a Python package dependency) for attestation:

    athena-testlab attest --report-dir ./run-001 --private-key ./lab-private-ed25519 --principal lab-maintainer
    athena-testlab verify-attestation --report-dir ./run-001 --allowed-signers ./trusted-signers --principal lab-maintainer

The trusted-signers file must contain the appropriate OpenSSH Ed25519 public key. Never commit the private key.

## Real upstream rAthena startup verification

On November 21, 2026, an isolated official rAthena container with a disposable MySQL database successfully ran login-server, char-server and map-server with --run-once. The installed Athena TestLab CLI recorded 3 PASS / 0 FAIL and hashed its sanitized log. This is a real server-startup test, **not** a successful Ragnarok client login. See [real upstream QA and image digests](docs/real-rathena-qa.md) for evidence and limitations. The disposable database was removed; existing ValkiRO containers were not touched.

## Security and limitations

Process execution is disabled by default. The operator authorizes a concrete file inside --workspace. Commands never pass through a shell and raw output is not reproduced in reports. TCP checks are loopback-only. A report directory must be new and outside the scanned workspace.

A successful TCP connection does not establish the Ragnarok login protocol, character selection or any client version compatibility. M6 can test a real negative rAthena login response, but no real account was authenticated. Optional positive packet tests require explicitly supplied temporary credentials through environment variables only; none were used in the upstream M6 QA. No GUI client or character automation is implemented. See [SECURITY.md](SECURITY.md).

## Development and QA

    python -m unittest discover -s tests -v
    python scripts/verify_release.py

The offline preflight checks version synchronization, JSON documents, tests, syntax and universal wheel build. For Linux without pip use --skip-wheel.

One current project checkpoint lives in [STATE.md](STATE.md); brief instructions live in [AGENTS.md](AGENTS.md). All test fixtures are synthetic; do not upload proprietary assets.
