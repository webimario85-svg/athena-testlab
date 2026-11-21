# Athena TestLab — single current continuity checkpoint

## Mission and guardrails
Standalone open-source, offline-first QA harness for rAthena; public repository https://github.com/webimario85-svg/athena-testlab .
No ValkiRO/RO Doctor code or private assets in this repository. Never publish binary clients, real accounts, SQL dumps, tokens or sensitive log contents. No GitHub Actions. Explicit operator authorization before launching game processes or sending authentication packets. Test outputs and large logs remain under ignored .qa/. See AGENTS.md for compact rules.

## Previous milestone (M5)
- v0.1.0 on main (commit 7c55a04d24bdc862addb58b4d1b9f3574830b26b): loopback TCP, bounded process testing, sanitized local evidence and RO Doctor v1 case files.
- Genuine official rAthena login-server/char-server/map-server --run-once tests passed 3/3 in disposable Docker/MySQL; not full client login. Details in docs/real-rathena-qa.md.
- 31/31 tests on Windows with portable smoke checks; public release tag v0.1.0.

## M6 completed on 2026-11-21
Feature worktree: D:\athena-testlab-m6 on feat/m6-login-protocol-evidence; base 7c55a04d24bdc862addb58b4d1b9f3574830b26b; feature commit efddb7a79b3c2eb2a8cf187f0c773b102e3e264f. PR #1 https://github.com/webimario85-svg/athena-testlab/pull/1 merged with squash commit 873991af6908bae3d680d8c1852395141b0af135. Main checkout D:\athena-testlab. Postmerge main release preflight PASS (v0.2.0, unit tests, source syntax, JSON, wheel). Release tag v0.2.0; confirm the current tag and HEAD through Git because the checkpoint's own commit follows this text. Older M6 feature worktree retained for inspection; next milestones need a new branch/worktree.

M6.1 — Actual protocol adapter
- New rathena-login test: sends real rAthena CA_LOGIN 0x0064 55-byte request, parses AC_REFUSE_LOGIN 0x083e (or legacy 0x006a) and AC_ACCEPT_LOGIN 0x0069 headers.
- Requires explicit --allow-login-probe, localhost-only, bounded timeouts; random nonregistering account for negative tests. Optional positive test credentials can only be read from process environment variables, never CLI or manifest; NOT tested against upstream in M6.
- Only a zero-error rejection for an intentionally absent account qualifies as an account-rejected PASS. The client_version field is a hint, not effective PACKETVER evidence.
- Optional RO Doctor case scenario is narrowly named rathena-account-rejected or rathena-login-accepted, not a general client compatibility success. The v1 JSON case contract remains unchanged.

M6.2 — Real upstream server QA
- Reused official pinned Docker images: rAthena sha256:d9f594008680a167e7048c1d48287d2cf9751ef3d4baf40043e707fe43e3fd32; MySQL 8.4 sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902; Python 3.13 Alpine sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8.
- Imported 22 official upstream SQL files into throwaway database; login and probe containers shared ONLY its isolated network namespace, no host-published ports.
- Actual rAthena returned 0x083e error 0 to a 0x0064 login packet for an unregistered account: PASS 1/1, report's first sanitized log SHA-256 70e7ff7cd7ed2b277abc4e8211f61275f1887f76dc736e31b372a3c4d6da1d57.
- Reusable scripts/run_isolated_rathena_login_lab.ps1 (PowerShell 5.1) pins the exact image IDs, imports official SQL, sends the packet and tears down only GUID-named lab containers. First rehearsal FAILED because random MySQL user password disagreed with the official image's public development configuration; test-only database credentials and cleanup were corrected. The next full script execution PASSED with exit 0 and zero remaining lab containers. All 16 ValkiRO containers remained running.
- Querying a login-account table was blocked by tool safety controls. No workarounds used. Positive authentication was not proven and no real Ragexe EXE was run.

M6.3 — Signed evidence without schema changes
- New opt-in OpenSSH ssh-keygen Ed25519 attest and verify-attestation commands. Canonical signed inventory covers run.json, session.log and optional case JSON files, with SHA-256 for each; explicit trusted allowed_signers public key validates the principal.
- Real upstream negative-login local report signature PASS; modified copy rejected; ephemeral test private key deleted. No raw logs, passwords, keys or private paths committed.
- Signature proves byte integrity and key possession for a configured signer, NOT execution truth, honest outcome, or full game compatibility.

M6.4 — QA, packaging and interoperability
- Version v0.2.0; Python >=3.10; universal wheel, stdlib runtime. OpenSSH executable required only for optional signatures.
- Windows 11 / Python 3.13.15: 58/58 unittest PASS, JSON documents/schemas, in-memory syntax, offline wheel build/content PASS; isolated venv wheel installation PASS.
- Ubuntu WSL / Python 3.14.4: 58/58 unittest PASS including OpenSSH signing tests; preflight PASS (wheel deliberately skipped due to no pip).
- Alpine Docker / Python 3.10.22: 58 tests executed, 11 skipped (OpenSSH/symlink privileges unavailable), remaining PASS; release preflight PASS with --network none, read-only source. Isolated wheel pip install into ephemeral filesystem PASS.
- Independent Athena TestLab 0.2.0 + RO Doctor 0.5.0 wheels were installed together on Windows and offline Alpine 3.10. A synthetic local 0x0064/0x083e exchange generated a precisely named v1 case and log; RO Doctor returned CASE_LOG_SHA256_MATCH + CASE_REPORTED_PASS for the rejection scenario. Tampered log was rejected with CASE_LOG_SHA256_MISMATCH. No claim of full Ragexe compatibility.
- Full logs and synthetic/real isolated evidence in ignored .qa/ only; no GitHub Actions and no modifications to RO Doctor or ValkiRO.
- Full protocol and lab method: docs/m6-protocol-and-evidence.md. Lab script: scripts/run_isolated_rathena_login_lab.ps1.

## Limits and next priority — M7
1. Independently prove positive account login in a separate, newly authorized disposable database with explicit local test credentials and no production access, then test char/map handoff. Do not reuse real credentials and do not bypass blocked account-table access.
2. Add a protocol matrix tied to independently identified server builds and supported client handshake variants, not arbitrary filename or version hints.
3. Consider public-key attestation ingestion in RO Doctor as a separately reviewed extension; never silently reinterpret its v1 data schema or claim signed logs establish execution truth.
4. Improve failure-case retry/teardown scenarios and widen safe fuzzing and OS packaging tests.
5. Resume by reading this checkpoint and real git/worktree/PR state. Preserve concurrent work and existing ValkiRO processes.
