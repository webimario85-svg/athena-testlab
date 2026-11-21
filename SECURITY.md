# Safety boundaries

Tests operate only against explicit loopback ports and user-designated workspace files. TCP probes never target arbitrary external hosts. Process tests are disabled unless --allow-exec is explicitly supplied; subprocesses launch with shell=False and a workspace-relative binary.

The harness records only test type, result, duration, byte counts and SHA-256 of captured output, never raw subprocess stdout/stderr or network payloads. An opt-in executable can access its own network independently of the TCP probe restrictions, so isolate subprocesses with containers/OS permissions when required. Generated records must be reviewed before sharing. Never use real account secrets, personal records, proprietary game clients, or production server credentials in a public issue.

Test reports describe direct local observations, not proof of a successful Ragnarok client login. In particular, a successful TCP connection or process exit is not a Ragnarok protocol handshake. The optional RO Doctor-compatible case manifest records reported outcome for its named scenario and is independently reviewable only alongside the complete sanitized log. No game binaries or private assets are redistributed.

Contact maintainers privately for vulnerabilities.
