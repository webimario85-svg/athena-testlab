"""M6 OpenSSH signature and report-integrity tests (ephemeral keys only)."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from athenatestlab.attestation import sign, verify, AttestationError


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen unavailable")
class AttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.key = cls.base / "test-signing-key"
        proc = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                               "-N", "", "-f", str(cls.key)],
                              capture_output=True, timeout=20)
        if proc.returncode:
            raise RuntimeError("could not generate ephemeral test signing key")
        cls.pub = cls.base / "allowed_signers"
        pubkey = (cls.base / "test-signing-key.pub").read_text("utf8").strip()
        cls.pub.write_text("athena-lab " + pubkey + "\n", encoding="utf8")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.report = self.root / "report"
        self.report.mkdir()
        self.log = self.report / "session.log"
        self.log.write_text('{"event":"synthetic-test","passed":true}\n',
                            encoding="utf8")
        self.run = self.report / "run.json"
        self.run.write_text(json.dumps({
            "schema_version": "1", "suite_id": "synthetic-sample",
            "tests": [{"id": "tcp-only", "passed": True}]
        }), encoding="utf8")

    def test_sign_and_verify_local_ed25519(self):
        path = sign(self.report, self.key, "athena-lab")
        self.assertTrue(path.exists())
        self.assertTrue(verify(self.report, self.pub, "athena-lab")[
            "signature_verified"])

    def test_log_tampering_blocks_signature_verification(self):
        sign(self.report, self.key, "athena-lab")
        self.log.write_bytes(self.log.read_bytes() + b"x")
        with self.assertRaisesRegex(AttestationError, "SHA-256"):
            verify(self.report, self.pub, "athena-lab")

    def test_run_json_tampering_blocks_verification(self):
        sign(self.report, self.key, "athena-lab")
        self.run.write_bytes(b"{}")
        with self.assertRaises(AttestationError):
            verify(self.report, self.pub, "athena-lab")

    def test_wrong_principal_rejected(self):
        sign(self.report, self.key, "athena-lab")
        with self.assertRaisesRegex(AttestationError, "signer mismatch"):
            verify(self.report, self.pub, "somebody-else")

    def test_wrong_allowed_key_fails(self):
        sign(self.report, self.key, "athena-lab")
        wrong = self.root / "wrong"
        wrong.write_text("athena-lab ssh-ed25519 "
                         "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                         encoding="utf8")
        with self.assertRaises(AttestationError):
            verify(self.report, wrong, "athena-lab")

    def test_prevent_overwriting_signature(self):
        sign(self.report, self.key, "athena-lab")
        with self.assertRaisesRegex(AttestationError, "refusing overwrite"):
            sign(self.report, self.key, "athena-lab")

    def test_cases_included_and_tampering_detected(self):
        folder = self.report / "cases"
        folder.mkdir()
        one = folder / "synthetic.case.json"
        one.write_text('{"status":"unverified"}', encoding="utf8")
        sign(self.report, self.key, "athena-lab")
        self.assertEqual(verify(self.report, self.pub, "athena-lab")[
            "files_verified"], 3)
        one.write_text('{"status":"pass"}', encoding="utf8")
        with self.assertRaises(AttestationError):
            verify(self.report, self.pub, "athena-lab")

    def test_extra_file_invalidates_attestation(self):
        sign(self.report, self.key, "athena-lab")
        (self.report / "untracked.txt").write_text("tampering", encoding="utf8")
        with self.assertRaises(AttestationError):
            verify(self.report, self.pub, "athena-lab")

    def test_attestation_symlink_escape_is_rejected(self):
        outside = self.root / "outside-attestation.json"
        outside.write_text("{}", encoding="utf8")
        symlink = self.report / "attestation.json"
        try:
            symlink.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(AttestationError):
            verify(self.report, self.pub, "athena-lab")

    def test_no_private_key_inside_report(self):
        with self.assertRaisesRegex(AttestationError, "private key"):
            sign(self.report, self.run, "athena-lab")

    def test_signed_json_contains_no_absolute_paths_or_private_key(self):
        sign(self.report, self.key, "athena-lab")
        raw = (self.report / "attestation.json").read_text("utf8")
        self.assertNotIn(str(self.base), raw)
        self.assertNotIn(str(self.root), raw)
        self.assertNotIn("PRIVATE KEY", raw)
        parsed = json.loads(raw)
        self.assertEqual(parsed["namespace"], "athena-testlab")
        self.assertEqual(parsed["principal"], "athena-lab")


if __name__ == "__main__":
    unittest.main()
