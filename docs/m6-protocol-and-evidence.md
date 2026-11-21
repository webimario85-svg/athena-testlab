# M6: real rAthena login-packet observation and signed evidence

M6 extends Athena TestLab v0.2.0 with a real login-packet probe and optional OpenSSH Ed25519 report signatures. Neither feature claims that a specific Ragexe client can complete login, character selection, or gameplay.

## Grounded packet contract

Sources: https://github.com/rathena/rathena/blob/master/src/common/packets.hpp and https://github.com/rathena/rathena/blob/master/src/login/loginclif.cpp

- CA_LOGIN 0x0064: packed 55-byte client request, uint16 opcode, uint32 client-version hint, 24-byte username, 24-byte password, uint8 clienttype.
- AC_REFUSE_LOGIN 0x083e: modern response, uint16 opcode, uint32 error and 20-byte unblock text. Historical response 0x006a has an 8-bit error.
- AC_ACCEPT_LOGIN 0x0069: a login acceptance packet header. Its presence alone does not prove a working Ragexe game session.

The new rathena-login test requires --allow-login-probe, literal loopback 127.0.0.1 or ::1, a bounded timeout, a version hint and an expected outcome:

- account-rejected: generate a random account name without _M/_F registration suffix, send 0x0064, require a real refusal with error code 0. Output observation account-rejection-confirmed. This is not successful authentication.
- accepted: operator must explicitly provision a disposable test account; username and password are taken ONLY from environment ATHENA_TESTLAB_LOGIN_USER and ATHENA_TESTLAB_LOGIN_PASSWORD, never suite JSON or CLI. Only a bounded 0x0069 packet header counts. No session token/payload is copied into evidence.

No accounts are created by the tool. Never probe production login servers or use real user accounts.

### Negative test manifest

    {
      "schema_version": "1",
      "suite_id": "real-rathena-negative-login",
      "tests": [{
        "id": "unknown-account",
        "kind": "rathena-login",
        "host": "127.0.0.1",
        "port": 6900,
        "timeout_ms": 3500,
        "client_version": 20211103,
        "expect": "account-rejected"
      }]
    }

Run only from within the disposable server's loopback network namespace:

    athena-testlab run --manifest suite.json --workspace ./empty-workspace --output ./new-report-dir --allow-login-probe

The client_version field is merely a packet hint, not proof that a Ragexe version/PACKETVER is supported.

## Actual upstream protocol test: November 21, 2026

Pinned local images:
- rathena/rathena-renewal, image ID sha256:d9f594008680a167e7048c1d48287d2cf9751ef3d4baf40043e707fe43e3fd32
- mysql:8.4, image ID sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902
- python:3.13-alpine, image ID sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8

Imported 22 official SQL files into a disposable MySQL instance. The login-server and Python probe shared only its isolated Docker network namespace; no ports were published on the host. The real rAthena login-server returned 0x083e/error 0 following a real 0x0064 packet from TestLab. Observed outcome: 1 PASS, 0 FAIL, account-rejection-confirmed. Initial sanitized report log SHA-256: 70e7ff7cd7ed2b277abc4e8211f61275f1887f76dc736e31b372a3c4d6da1d57.

The full lab was independently re-executed through scripts/run_isolated_rathena_login_lab.ps1. The final repeat passed, removed its own uniquely named MySQL/login containers and left all 16 running ValkiRO containers untouched. An initial script trial failed because randomized disposable database-user credentials disagreed with upstream image defaults. The final isolated DB uses the PUBLIC development account/password ragnarok/ragnarok inside the unpublished namespace, while the MySQL root password remains randomized. Cleanup was hardened for containers already exited.

Positive authentication was not run. Account database inspection was blocked by tool safety controls; the tool did not work around that restriction. No actual Ragexe EXE took part; no client/server compatibility certificate is produced.

### Re-run with local pinned images

Requires Windows PowerShell 5.1+, Docker Desktop, the exact cached image IDs above, official SQL files from the matching rAthena image and a preexisting scratch parent directory:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run_isolated_rathena_login_lab.ps1 -SqlDirectory "D:\official-rathena-sql" -WorkDirectory "D:\athena-qa"

The script creates a uniquely named scratch directory and removes only the containers it created. It never publishes ports, touches existing ValkiRO containers or mounts production data. Do not substitute production SQL or credentials.

## OpenSSH Ed25519 report signing

The optional attestation feature signs a SHA-256 inventory of run.json, session.log and optional cases/*.json files. No private key, raw log, absolute source path, client binary or SQL file enters attestation.json.

    athena-testlab attest --report-dir ./qa-run --private-key ./private-ed25519-key --principal testlab-maintainer
    athena-testlab verify-attestation --report-dir ./qa-run --allowed-signers ./trusted-signers --principal testlab-maintainer

The trusted-signers file is an OpenSSH allowed_signers document mapping principal to a trusted ssh-ed25519 public key. A different signer, changed file, added artifact, modified case or broken signature fails verification. The signature proves that a holder of the locally trusted private key signed the report bytes. It does NOT independently prove the test occurred or that the reported results are accurate.

The real upstream negative-test report was signed and verified with an ephemeral local Ed25519 key. Verification rejected a deliberately tampered copy. The test private key was destroyed. Reports and trusted test public key remained only in ignored local .qa/ directories.

The core has no third-party Python runtime dependencies; OpenSSH ssh-keygen is only needed for optional attest/verify commands.

## RO Doctor v0.5.0 interoperability

RO Doctor's JSON case schema v1 remains unchanged. If *both* actual client and server binary inputs are supplied, M6 distinguishes rathena-account-rejected, rathena-login-accepted and rathena-login-probe scenarios. RO Doctor can verify case and log SHA-256 using its existing interface. It does not independently verify the SSH attestation without further work.

For the genuine upstream negative account test, no actual client EXE was supplied, so TestLab deliberately produced no misleading client/server compatibility case. The separate M5 cross-project integration smoke remains valid for a synthetic TCP exchange only.
