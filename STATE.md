# Athena TestLab — current checkpoint

## Project
Standalone public tool, repository https://github.com/webimario85-svg/athena-testlab, local checkout D:\athena-testlab on main. Completely independent from ValkiRO and RO Doctor. No private code or copyrighted game assets in Git. Progress is stored in this one STATE.md; short rules in AGENTS.md. No GitHub Actions.

## M5 multi-milestone delivery (2026-11-21)
- M5.1: created new public repo and Python 3.10+ standalone CLI/package with independent license and docs. First release v0.1.0.
- M5.2: strict v1 suite JSON manifest with bounded tests, real loopback TCP open, byte-exchange probe, and explicit opt-in OS process-exit runner. Process invocation is workspace-relative, shell=False with timeout/byte caps. No raw stdout/stderr or socket payloads in public logs. These checks never claim a Ragnarok login.
- M5.3: local run.json, sanitized session.log and optional case artifacts using the RO Doctor case JSON v1 contract and exact local binary SHA-256. Clean-venv installed wheels of Athena TestLab and independent RO Doctor v0.5.0 exchanged and validated evidence successfully in Windows and offline Alpine/Python 3.10. Local synthetic TCP fixture only; not a game handshake.
- M5.4: real official upstream rAthena container run-once validation using a disposable MySQL 8.4 container in network-none namespace with no published ports. Imported 22 official SQL files and observed real login-server, char-server and map-server each return exit 0. Athena TestLab's installed CLI captured 3 PASS / 0 FAIL; before DB setup the map-server legitimately failed with missing MySQL (recorded, not concealed). See docs/real-rathena-qa.md for exact image IDs and scope. Disposed DB and verified all 16 ValkiRO containers remained running.
- M5.5: added synthetic unit tests for manifest validation, path traversal, safe execution, process timeouts/output cap, real local TCP, evidence checksums, false-positive prevention. Offline release preflight and wheel packaging. 31/31 unit tests PASS on NoteNitro5 Windows Python 3.13.15. Python 3.14.4 WSL Ubuntu, Python 3.10.22/3.13.18 Linux Alpine isolated Docker also PASS. Linux 3.10 independent wheel-to-wheel interop PASS; Windows clean venv wheel-to-wheel interop PASS.
- All local QA reports, test database source SQL files, disposable image metadata and logs are under ignored .qa/. No remote production access or branch edits in ValkiRO or RO Doctor.
- Git state: initial standalone repository main bootstrap; get actual commit/tag via git log -1 and git tag -l. No PR required for bootstrap. Ensure future work starts from current branch state rather than replaying M5.

## Important limits
- A passing TCP-open or tcp-exchange test establishes only that exact socket observation. A passing process-exit establishes only that an executable exited with the expected code. None prove successful Ragexe game login, specific client protocol support, map loading under gameplay, or player authentication.
- The official rAthena Docker image is pinned by image ID in docs for traceability; it may differ from current master source. The test used default server configs with a throwaway DB.
- A case file is only emitted when both binary files are explicitly provided, so genuine server startup checks without a client never invent a successful client compatibility result.
- No automatic test signing, authenticated attestation or remote runner. No production DB and no outbound TCP probes; opt-in subprocesses can have their own networking and must be externally isolated by the operator.
- Raw process output intentionally withheld from public evidence; only summarized exit codes and output hashes recorded. Troubleshooting can be performed in a separate explicitly authorized local sandbox.

## Next priority — M6
1. Build genuine protocol-level adapter for controlled rAthena test servers (do not confuse a port probe with login), with packet version matrices and strict no-secrets logging.
2. Add explicit local evidence-log signature/identity verification and optional signed runner records without changing RO Doctor's schema silently.
3. Dedicated disposable DB/container harness with robust teardown, pinned image digests and a repeatable local release runner; avoid touching active ValkiRO services.
4. Extend property/fuzz fixtures and validate on CI-like local executors only (no GitHub Actions).
