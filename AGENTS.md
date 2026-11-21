# Contributor rules

- This is a completely independent public tool: no ValkiRO code, accounts, GRFs or Ragexe binaries in this repository.
- Inspect Git HEAD, branch, worktrees, PRs and concurrent work before editing. Never overwrite parallel changes.
- Keep one current checkpoint in STATE.md. Keep logs/artifacts in ignored .qa/ or reports/.
- Never claim a real Ragnarok login or packet compatibility from a TCP connect, a synthetic listener or an exit code.
- Process execution is opt-in and workspace-scoped. No shell. Built-in TCP probes are loopback-only; subprocess networking must be isolated separately by the operator. Never point a test at production databases or services.
- Test synthetic fixtures and negative cases. No GitHub Actions. Use local/isolated executors.
- A case file may report a real transport/test outcome only for its exact named scenario; full game compatibility remains unverified without a real client/server handshake.
- M6 rathena-login sends a genuine login packet only on loopback with explicit --allow-login-probe; positive credentials come from ephemeral environment variables, not manifest or logs. Protocol rejection is not successful authentication.
- M6 attestation uses optional external OpenSSH signing keys and an explicit allowed_signers trust file; never commit private keys or treat a valid signature as proof a game test occurred.
