"""Optional OpenSSH Ed25519 evidence attestations, independent of RO Doctor.

No raw log bytes, keys or absolute paths enter the signed manifest.
Signature proves possession of the trusted key, not truth of the test claims.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

NAMESPACE = "athena-testlab"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
MAX_RUN = 512 * 1024
MAX_LOG = 128 * 1024 * 1024
MAX_CASE = 64 * 1024
MAX_CASES = 64
MAX_ATTEST = 64 * 1024


class AttestationError(ValueError):
    pass


def _sha(path: Path, limit: int, base: Path) -> str:
    try:
        if not path.is_file() or not path.resolve().is_relative_to(base.resolve()):
            raise AttestationError("invalid or escaped evidence file")
        size = path.stat().st_size
        if size > limit:
            raise AttestationError("evidence file exceeds its inspection bound")
        digest = hashlib.sha256()
        consumed = 0
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                consumed += len(block)
                if consumed > limit:
                    raise AttestationError("evidence file grew beyond its bound")
                digest.update(block)
        if consumed != size:
            raise AttestationError("evidence file changed while reading")
        return digest.hexdigest()
    except OSError:
        raise AttestationError("evidence file is not readable") from None


def _inventory(report_dir: Path) -> list[dict]:
    try:
        if not report_dir.is_dir():
            raise AttestationError("missing report directory")
        root = report_dir.resolve()
        run = report_dir / "run.json"
        log = report_dir / "session.log"
        if not run.is_file() or not log.is_file():
            raise AttestationError("missing run.json or session.log")
        files = [
            {"name": "run.json", "sha256": _sha(run, MAX_RUN, root)},
            {"name": "session.log", "sha256": _sha(log, MAX_LOG, root)},
        ]
        # Sign only the TestLab-generated case manifests, never arbitrary
        # external paths or game binaries.
        case_dir = report_dir / "cases"
        if case_dir.exists():
            if not case_dir.is_dir() or not case_dir.resolve().is_relative_to(root):
                raise AttestationError("unsafe cases directory")
            cases = sorted(case_dir.iterdir(), key=lambda p: p.name)
            if len(cases) > MAX_CASES:
                raise AttestationError("too many cases to attest")
            for case in cases:
                if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,150}\.json", case.name)
                        or not case.is_file()):
                    raise AttestationError("invalid case artifact")
                files.append({"name": "cases/" + case.name,
                              "sha256": _sha(case, MAX_CASE, root)})
        # Reject untracked arbitrary files: every byte in the report must be
        # accounted for, except the signature metadata itself.
        found = set()
        for entry in report_dir.iterdir():
            if entry.name == "cases":
                continue
            if entry.name == "attestation.json":
                continue
            if entry.is_file() and entry.name in {"run.json", "session.log"}:
                found.add(entry.name)
                continue
            raise AttestationError("unrecognized report artifact")
        if found != {"run.json", "session.log"}:
            raise AttestationError("missing expected report artifacts")
        return files
    except (OSError, ValueError) as ex:
        if isinstance(ex, AttestationError):
            raise
        raise AttestationError("cannot inspect report artifacts") from None


def _payload(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _ssh(args: list[str], data: bytes) -> bytes:
    if shutil.which("ssh-keygen") is None:
        raise AttestationError("OpenSSH ssh-keygen not available")
    try:
        done = subprocess.run(["ssh-keygen", *args], input=data, capture_output=True,
                              timeout=25, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise AttestationError("OpenSSH signature operation unavailable") from None
    if done.returncode != 0:
        raise AttestationError("OpenSSH signature operation rejected the evidence")
    return done.stdout


def sign(report_dir: Path, private_key: Path, principal: str) -> Path:
    if not isinstance(principal, str) or not ID_RE.fullmatch(principal):
        raise AttestationError("invalid signer principal")
    root = report_dir.resolve()
    if private_key.resolve().is_relative_to(root):
        raise AttestationError("private key cannot live inside the report directory")
    if not private_key.is_file():
        raise AttestationError("private key is not a file")
    output = report_dir / "attestation.json"
    if output.exists():
        raise AttestationError("attestation exists; refusing overwrite")
    evidence = {"schema_version": "1", "principal": principal,
                "namespace": NAMESPACE, "files": _inventory(report_dir)}
    signature = _ssh(["-Y", "sign", "-f", str(private_key), "-n", NAMESPACE],
                     _payload(evidence)).decode("utf-8", errors="strict")
    if ("-----BEGIN SSH SIGNATURE-----" not in signature or
            "-----END SSH SIGNATURE-----" not in signature):
        raise AttestationError("OpenSSH produced an unrecognized signature")
    final = dict(evidence)
    final["signature"] = signature
    output.write_bytes(_payload(final))
    return output


def verify(report_dir: Path, allowed_signers: Path,
           principal: str) -> dict:
    if not isinstance(principal, str) or not ID_RE.fullmatch(principal):
        raise AttestationError("invalid expected signer")
    if not allowed_signers.is_file():
        raise AttestationError("trusted allowed signers file is missing")
    path = report_dir / "attestation.json"
    try:
        if not path.resolve().is_relative_to(report_dir.resolve()):
            raise AttestationError("attestation escaped the report directory")
        if not path.is_file() or path.stat().st_size > MAX_ATTEST:
            raise AttestationError("attestation missing or too large")
        content = path.read_bytes()
        if len(content) > MAX_ATTEST:
            raise AttestationError("attestation too large")
        attested = json.loads(content)
    except (OSError, ValueError, json.JSONDecodeError):
        raise AttestationError("attestation is invalid JSON") from None
    if (not isinstance(attested, dict) or
            set(attested) != {"schema_version", "principal", "namespace",
                             "files", "signature"} or
            attested.get("schema_version") != "1" or
            attested.get("namespace") != NAMESPACE or
            attested.get("principal") != principal or
            not isinstance(attested.get("signature"), str)):
        raise AttestationError("attestation schema or signer mismatch")
    signature = attested["signature"]
    if (len(signature) > 16000 or
            not signature.startswith("-----BEGIN SSH SIGNATURE-----") or
            "-----END SSH SIGNATURE-----" not in signature):
        raise AttestationError("invalid signature payload")
    actual_files = _inventory(report_dir)
    if attested["files"] != actual_files:
        raise AttestationError("report inventory SHA-256 mismatch")
    signed_obj = {key: value for key, value in attested.items() if key != "signature"}
    with tempfile.TemporaryDirectory() as scratch:
        sig_path = Path(scratch) / "signature.txt"
        sig_path.write_text(signature, encoding="utf8")
        _ssh(["-Y", "verify", "-f", str(allowed_signers), "-I",
              principal, "-n", NAMESPACE, "-s", str(sig_path)],
             _payload(signed_obj))
    return {"principal": principal, "files_verified": len(actual_files),
            "signature_verified": True, "claim_not_independently_proven": True}
