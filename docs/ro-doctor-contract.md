# Independent interoperability with RO Doctor

Athena TestLab and RO Doctor are separate projects, with no shared source tree or direct runtime dependency. TestLab produces bounded local evidence and optional case manifests matching the RO Doctor test-case v1 schema.

## Generate cases

Supply both actual binary files within the workspace with --client-exe and --server-exe. Athena TestLab independently computes their exact SHA-256 bytes. No hashes can be typed manually or inferred from client dates.

    athena-testlab run --manifest /tmp/suite.json --workspace /srv/lab --output /tmp/run-001 --client-exe Ragexe.exe --server-exe map-server

The output contains run.json, sanitized session.log and one JSON artifact per test under cases/. Each case has an exact scenario (tcp-open, tcp-exchange or process-exit); reported pass/fail for only that test kind; both binary fingerprints; the SHA-256 checksum for the actual sanitized session.log; the UTC date and a source URL.

RO Doctor v0.5.0 can independently inspect the local artifacts:

    rodoctor --client /srv/lab --case-file /tmp/run-001/cases/rathena-local-smoke.login-port-check.json --case-log /tmp/run-001/session.log --server-build-sha256 ACTUAL_MAP_SERVER_HASH --only-check case-evidence --format json

RO Doctor scans Ragexe/Ragnarok-named client executables. Use --client-exe if selection is ambiguous. The server build hash must be the SHA-256 measured from the same actual file.

## Trust boundaries

A pass is a local observation only of the named TCP/process probe. It is not proof of character selection, PACKETVER compatibility, authentication, map loading or a functioning Ragnarok client. This suite format does not implement a Ragnarok login protocol handshake. RO Doctor validates hashes/log bytes, not who generated the evidence.

The built-in interoperability smoke uses a synthetic TCP responder and placeholder client/server binaries, not a real game login. Authentic rAthena execution requires an actual rAthena binary and separate authorized test environment.

No proprietary assets, client builds, credentials or production tokens are bundled.
