# M5 genuine upstream rAthena startup QA

Recorded: 2026-11-21, Windows NoteNitro5 with Docker Desktop. **This was a real upstream server executable test, NOT a Ragnarok client login or protocol compatibility test.**

## Inputs

- Public Docker image rathena/rathena-renewal:latest, image ID sha256:d9f594008680a167e7048c1d48287d2cf9751ef3d4baf40043e707fe43e3fd32.
- Disposable MySQL 8.4 image ID sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902.
- 22 upstream SQL files copied from the rAthena image's own sql-files directory and imported into an ephemeral ragnarok database.
- No GRFs, private server contents, client executable, real login account, or production credentials.
- No published host ports. Database container used --network none; tested server container joined only its isolated network namespace, so localhost:3306 pointed to the disposable database.
- Server processes used --read-only and an ephemeral /tmp, with memory, CPU and process limits.
- At no point were the existing ValkiRO containers, networks or volumes modified.

## Actual milestones and outcomes

1. Without a database, a genuine map-server --run-once returned exit code 1. Local diagnostics indicated that it could not connect to MySQL at 127.0.0.1:3306. That FAIL was preserved in the ignored local QA record.
2. Started a disposable MySQL instance with no published ports, imported 22 SQL files, confirmed database readiness.
3. Ran official login-server --run-once: exit code 0.
4. Ran official char-server --run-once: exit code 0.
5. Ran official map-server --run-once: exit code 0.
6. Repeated all three process checks through the installed Athena TestLab CLI, with workspace-restricted Docker executable and explicit --allow-exec, producing 3 PASS / 0 FAIL in local run.json. The map server check took about 40.9 seconds on this host.
7. Stopped and removed the dedicated MySQL container, no host ports ever opened. Verified all 16 previously running ValkiRO containers were still running.

Sanitized log SHA-256: 3824ca8c37ff68e0e9a2ce39b28ac15e068cf2f45ea14da373428c45ffc430f4.

The actual log and inputs are retained **only under ignored D:\athena-testlab\.qa\official-complete-run**. This record does not make a publicly verifiable claim that anyone can validate the underlying log contents from Git alone; the hash is a local checkpoint.

## Relationship to RO Doctor

A separate cross-project smoke used real localhost TCP bytes with a synthetic responder and synthetic binary placeholders. The TestLab exported case JSON v1 and a sanitized session.log; independently installed RO Doctor v0.5.0 returned CASE_LOG_SHA256_MATCH and CASE_REPORTED_PASS for the precisely named tcp-exchange scenario. The RO Doctor protocol verifier does not certify Ragnarok login.

We deliberately did NOT export a fake successful Ragexe case from the official rAthena --run-once tests because no actual client executable participated in these startup-only checks.

## Reproduction notes

Use a new, uniquely named disposable database container with no published ports and a root password strictly for the test. Copy SQL files from the same pinned rAthena image. Validate your DB is ready before running --run-once. Invoke the three genuine official server binaries only in read-only, resource-limited containers that share this disposable network namespace; then run the same commands using Athena TestLab process-exit suites. Never mount or stop a production server or use a shared database.

rAthena official development validation guidance: https://github.com/rathena/rathena/blob/master/.github/workflows/npc_db_validation.yml
Official Docker instructions: https://github.com/rathena/rathena/blob/master/tools/docker/README.md

Full in-game session and PACKETVER compatibility remain untested. That requires a permitted real Ragexe client and separate protocol/client QA runner.
