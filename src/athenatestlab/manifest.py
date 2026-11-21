"""Strict v1 suite manifest validation (untrusted local JSON).

A test is only a narrow observation: TCP open, TCP byte exchange, or an
explicitly authorized workspace-relative program exit.
"""
from pathlib import Path
import json
import re

MAX_MANIFEST_BYTES = 128 * 1024
MAX_TESTS = 64
ID = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){0,256}$")
HOSTS = {"127.0.0.1", "::1"}
KINDS = {"tcp-open", "tcp-exchange", "process-exit"}


class ManifestError(ValueError):
    pass


def safe_relative(value: object) -> str:
    """Validate a simple portable relative file path; resolve separately."""
    if not isinstance(value, str):
        raise ManifestError("expected relative file path")
    norm = value.replace("\\", "/")
    segments = norm.split("/")
    if (not norm or len(norm) > 240 or norm.startswith("/")
            or ":" in norm or len(segments) > 20
            or any(x in ("", ".", "..") for x in segments)
            or not re.fullmatch(r"[A-Za-z0-9_ +./@-]+", norm)):
        raise ManifestError("invalid workspace-relative file path")
    return norm


def inside_workspace(root: Path, relative: object) -> Path:
    norm = safe_relative(relative)
    target = root / norm
    try:
        if not target.resolve().is_relative_to(root.resolve()):
            raise ManifestError("file resolves outside workspace")
    except (OSError, ValueError):
        raise ManifestError("cannot resolve workspace path") from None
    return target


def _keys(item: dict, expected: set[str]) -> None:
    if set(item) != expected:
        raise ManifestError("invalid test fields")


def _timeout(value: object) -> int:
    if type(value) is not int or not 50 <= value <= 120000:
        raise ManifestError("timeout_ms must be 50 to 120000")
    return value


def _port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ManifestError("invalid local TCP port")
    return value


def _test(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ManifestError("test must be a JSON object")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        raise ManifestError("unknown test kind")
    if not isinstance(raw.get("id"), str) or not ID.fullmatch(raw["id"]):
        raise ManifestError("invalid test id")
    _timeout(raw.get("timeout_ms"))
    if kind == "tcp-open":
        _keys(raw, {"id", "kind", "host", "port", "timeout_ms"})
        if not isinstance(raw["host"], str) or raw["host"] not in HOSTS:
            raise ManifestError("only loopback TCP probes are allowed")
        _port(raw["port"])
    elif kind == "tcp-exchange":
        _keys(raw, {"id", "kind", "host", "port", "timeout_ms",
                    "send_hex", "expect_hex"})
        if not isinstance(raw["host"], str) or raw["host"] not in HOSTS:
            raise ManifestError("only loopback TCP probes are allowed")
        _port(raw["port"])
        for key in ("send_hex", "expect_hex"):
            if not isinstance(raw[key], str) or not HEX.fullmatch(raw[key]):
                raise ManifestError("invalid bounded hex payload")
        if not raw["expect_hex"]:
            raise ManifestError("expected bytes must not be empty")
    elif kind == "process-exit":
        _keys(raw, {"id", "kind", "executable", "args",
                    "expect_exit", "timeout_ms"})
        safe_relative(raw["executable"])
        args = raw["args"]
        if (not isinstance(args, list) or len(args) > 12
                or any(not isinstance(a, str) or len(a) > 200
                       or any(ord(c) < 32 for c in a) for a in args)):
            raise ManifestError("invalid bounded process argument array")
        if type(raw["expect_exit"]) is not int or not -1000 <= raw["expect_exit"] <= 1000:
            raise ManifestError("invalid expected exit code")
    return raw.copy()


def load_manifest(path: Path) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest missing or exceeds 128 KiB")
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest exceeds 128 KiB")
        obj = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ManifestError("manifest cannot be read as JSON") from None
    if not isinstance(obj, dict) or set(obj) != {
        "schema_version", "suite_id", "tests"
    } or obj.get("schema_version") != "1":
        raise ManifestError("invalid v1 manifest schema")
    if not isinstance(obj["suite_id"], str) or not ID.fullmatch(obj["suite_id"]):
        raise ManifestError("invalid suite_id")
    tests = obj["tests"]
    if not isinstance(tests, list) or not 1 <= len(tests) <= MAX_TESTS:
        raise ManifestError("expected 1 to 64 tests")
    checked = [_test(t) for t in tests]
    if len({t["id"] for t in checked}) != len(checked):
        raise ManifestError("duplicate test id")
    return {"schema_version": "1", "suite_id": obj["suite_id"], "tests": checked}
