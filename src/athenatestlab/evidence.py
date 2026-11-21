"""Sanitized, independently hashable local evidence and RO Doctor case v1.

An outcome PASS applies only to the exact executed test kind and NOT to
Ragexe protocol compatibility. A matching hash says nothing about authorship.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .manifest import inside_workspace, ManifestError

MAX_BIN_BYTES = 250 * 1024 * 1024


def safe_source(url: str) -> bool:
    if not isinstance(url, str) or len(url) > 300:
        return False
    if any(ord(c) <= 32 for c in url):
        return False
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment
                and parsed.port in (None, 443))
    except ValueError:
        return False


def file_sha(path: Path) -> str:
    """Bounded content SHA-256, refuses directories and symlinks outside root upstream."""
    if not path.is_file():
        raise ManifestError("evidence binary not found")
    try:
        size = path.stat().st_size
        if size > MAX_BIN_BYTES:
            raise ManifestError("evidence binary exceeds 250 MiB")
        digest = hashlib.sha256()
        count = 0
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > MAX_BIN_BYTES:
                    raise ManifestError("evidence binary grew beyond 250 MiB")
                digest.update(block)
        if count != size:
            raise ManifestError("evidence binary changed during hashing")
        return digest.hexdigest()
    except OSError:
        raise ManifestError("cannot read evidence binary") from None


def encode(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def emit(manifest: dict, outcomes: list[dict], output: Path, root: Path, *,
         client_exe: str | None = None, server_exe: str | None = None,
         source_url: str = "https://github.com/webimario85-svg/athena-testlab") -> dict:
    if (client_exe is None) != (server_exe is None):
        raise ManifestError("client and server executable fingerprints must be supplied together")
    if not safe_source(source_url):
        raise ManifestError("source URL must be an HTTPS reference without credentials/query")
    # Compute fingerprints before creating any output directory.
    hashes = None
    if client_exe is not None:
        hashes = (file_sha(inside_workspace(root, client_exe)),
                  file_sha(inside_workspace(root, server_exe)))
    try:
        if output.resolve().is_relative_to(root.resolve()):
            raise ManifestError("output must be outside the selected workspace")
    except OSError:
        raise ManifestError("cannot resolve output location") from None
    if output.exists():
        raise ManifestError("output directory already exists; refuse overwrite")
    if not output.parent.is_dir():
        raise ManifestError("output parent directory does not exist")
    output.mkdir()
    now = datetime.now(timezone.utc)
    run = {
        "schema_version": "1",
        "tool": "athena-testlab",
        "version": __version__,
        "suite_id": manifest["suite_id"],
        "observed_at": now.isoformat(),
        "summary": {"passed": sum(t["passed"] for t in outcomes),
                    "failed": sum(not t["passed"] for t in outcomes)},
        "tests": outcomes,
        "interpretation": ("Results verify only named local process/TCP probes, "
                           "not a real Ragnarok protocol handshake."),
    }
    # A single stable, sanitized log file is shared by case artifacts.
    lines = [encode({"event": "suite-start", "suite_id": manifest["suite_id"],
                     "runner": f"athena-testlab/{__version__}"})]
    lines.extend(encode({"event": "test-result", **result}) for result in outcomes)
    lines.append(encode({"event": "suite-end", "summary": run["summary"]}))
    log_bytes = b"".join(lines)
    (output / "session.log").write_bytes(log_bytes)
    log_hash = hashlib.sha256(log_bytes).hexdigest()
    (output / "run.json").write_bytes(encode(run))
    if hashes is not None:
        cases_dir = output / "cases"
        cases_dir.mkdir()
        for test in outcomes:
            identifier = f"{manifest['suite_id']}.{test['id']}"
            if len(identifier) > 63:
                identifier = identifier[:54] + "-" + hashlib.sha256(
                    identifier.encode()).hexdigest()[:8]
            # The result is strictly the named observation, not protocol compatibility.
            case = {
                "schema_version": "1", "case_id": identifier,
                "scenario": test["kind"], "client_sha256": hashes[0],
                "server_build_sha256": hashes[1],
                "status": "pass" if test["passed"] else "fail",
                "observed_at": now.date().isoformat(),
                "runner": f"athena-testlab/{__version__}",
                "log_sha256": log_hash, "source_url": source_url,
            }
            (cases_dir / f"{identifier}.json").write_bytes(encode(case))
    return run
