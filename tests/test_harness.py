"""M5 contract and real local probe tests. Synthetic fixtures, no game login."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from athenatestlab.cli import main
from athenatestlab.evidence import emit, file_sha
from athenatestlab.manifest import load_manifest, ManifestError, inside_workspace
from athenatestlab.runner import execute


class AthenaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.manifest = self.base / "suite.json"
        self.output = self.base / "report"

    def suite(self, tests, suite_id="test-suite"):
        doc = {"schema_version": "1", "suite_id": suite_id, "tests": tests}
        self.manifest.write_text(json.dumps(doc), encoding="utf-8")
        return self.manifest

    @staticmethod
    def tcp(kind, port, **extras):
        return dict(id="tcp-test", kind=kind, host="127.0.0.1", port=port,
                    timeout_ms=700, **extras)

    def server(self, reply=None):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        events = []

        def serve():
            try:
                listener.settimeout(3)
                try:
                    conn, _ = listener.accept()
                except (TimeoutError, OSError):
                    return  # Some argument-validation tests intentionally never connect.
                with conn:
                    conn.settimeout(1)
                    if reply is not None:
                        events.append(conn.recv(64))
                        conn.sendall(reply)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        return port, events

    def test_reject_external_host(self):
        self.suite([self.tcp("tcp-open", 6900) | {"host": "8.8.8.8"}])
        with self.assertRaisesRegex(ManifestError, "loopback"):
            load_manifest(self.manifest)

    def test_reject_invalid_ports(self):
        for port in (0, 65536, True, "6900"):
            self.suite([self.tcp("tcp-open", port)])
            with self.assertRaises(ManifestError):
                load_manifest(self.manifest)

    def test_reject_process_traversal_and_absolute(self):
        for path in ("../outside.exe", "/etc/passwd", "C:\\Windows\\cmd.exe"):
            self.suite([{"id": "process-test", "kind": "process-exit",
                         "executable": path, "args": [],
                         "expect_exit": 0, "timeout_ms": 200}])
            with self.assertRaises(ManifestError):
                load_manifest(self.manifest)

    def test_invalid_test_kind(self):
        self.suite([{"id": "wrong-test", "kind": "unknown", "timeout_ms": 500}])
        with self.assertRaises(ManifestError):
            load_manifest(self.manifest)

    def test_duplicate_ids(self):
        test = self.tcp("tcp-open", 1)
        self.suite([test, test])
        with self.assertRaisesRegex(ManifestError, "duplicate"):
            load_manifest(self.manifest)

    def test_reject_unexpected_fields(self):
        self.suite([self.tcp("tcp-open", 2) | {"secret": "unsafe"}])
        with self.assertRaises(ManifestError):
            load_manifest(self.manifest)

    def test_manifest_max_bytes(self):
        self.manifest.write_bytes(b" " * (129 * 1024))
        with self.assertRaises(ManifestError):
            load_manifest(self.manifest)

    def test_reject_outside_workspace_symlink(self):
        outside = self.base / "external"
        outside.write_bytes(b"not executable")
        link = self.workspace / "link.exe"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink privileges not available")
        with self.assertRaises(ManifestError):
            inside_workspace(self.workspace, "link.exe")

    def test_real_tcp_open(self):
        port, _ = self.server()
        outcome = execute(self.tcp("tcp-open", port), self.workspace,
                          allow_exec=False)
        self.assertTrue(outcome["passed"])
        self.assertEqual(outcome["observation"], "tcp-port-accepted")

    def test_real_tcp_exchange(self):
        port, events = self.server(bytes.fromhex("aa55"))
        sample = self.tcp("tcp-exchange", port, send_hex="0102",
                          expect_hex="aa55")
        observed = execute(sample, self.workspace, allow_exec=False)
        self.assertTrue(observed["passed"])
        self.assertEqual(observed["observation"], "tcp-bytes-matched")
        self.assertNotIn("aa55", repr(observed))
        self.assertNotIn("0102", repr(observed))
        self.assertEqual(observed["sent_bytes"], 2)

    def test_tcp_exchange_wrong_bytes_fails(self):
        port, _ = self.server(bytes.fromhex("aabb"))
        sample = self.tcp("tcp-exchange", port, send_hex="0102",
                          expect_hex="aa55")
        result = execute(sample, self.workspace, allow_exec=False)
        self.assertFalse(result["passed"])
        self.assertEqual(result["observation"], "tcp-bytes-differed")

    def test_closed_local_port_fails(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        observed = execute(self.tcp("tcp-open", port), self.workspace,
                           allow_exec=False)
        self.assertFalse(observed["passed"])

    def test_process_requires_explicit_opt_in(self):
        test = {"id": "process-test", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["--version"], "expect_exit": 0,
                "timeout_ms": 4000}
        observed = execute(test, Path(sys.executable).parent,
                           allow_exec=False)
        self.assertEqual(observed["observation"], "execution-not-authorized")

    def test_real_process_exit_and_redacted_output(self):
        test = {"id": "process-test", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["-c", "print('SECRET_PASSWORD_SHOULD_NOT_LEAK')"],
                "expect_exit": 0, "timeout_ms": 4000}
        observed = execute(test, Path(sys.executable).parent,
                           allow_exec=True)
        self.assertTrue(observed["passed"], observed)
        self.assertEqual(observed["observation"], "expected-exit-observed")
        self.assertGreater(observed["output_bytes"], 0)
        self.assertNotIn("SECRET_PASSWORD", repr(observed))

    def test_process_timeout_enforced(self):
        test = {"id": "process-timeout", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["-c", "import time; time.sleep(1)"],
                "expect_exit": 0, "timeout_ms": 50}
        observed = execute(test, Path(sys.executable).parent, allow_exec=True)
        self.assertFalse(observed["passed"])
        self.assertEqual(observed["observation"], "process-timeout")

    def test_cli_reject_process_without_permission(self):
        self.suite([{"id": "process-test", "kind": "process-exit",
                     "executable": "fake.exe", "args": [], "expect_exit": 0,
                     "timeout_ms": 300}])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace),
                      "--output", str(self.output)])
        self.assertEqual(err.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_cli_tcp_run_emits_report_and_sanitized_log(self):
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", "--manifest", str(self.manifest),
                         "--workspace", str(self.workspace),
                         "--output", str(self.output)])
        self.assertEqual(code, 0)
        report = json.loads((self.output / "run.json").read_text())
        self.assertEqual(report["summary"], {"passed": 1, "failed": 0})
        self.assertEqual(report["tests"][0]["observation"],
                         "tcp-port-accepted")
        self.assertIn(b"tcp-port-accepted", (self.output / "session.log").read_bytes())
        self.assertNotIn(b"password", (self.output / "session.log").read_bytes())

    def test_case_manifest_is_ro_doctor_schema_compatible(self):
        client = self.workspace / "Ragexe.exe"
        server = self.workspace / "map-server.exe"
        client.write_bytes(b"MZsynthetic-client")
        server.write_bytes(b"MZsynthetic-server")
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", "--manifest", str(self.manifest),
                         "--workspace", str(self.workspace), "--output", str(self.output),
                         "--client-exe", client.name, "--server-exe", server.name])
        self.assertEqual(code, 0)
        case = json.loads(next((self.output / "cases").glob("*.json")).read_text())
        self.assertEqual(case["scenario"], "tcp-open")
        self.assertEqual(case["status"], "pass")
        self.assertEqual(case["client_sha256"], hashlib.sha256(client.read_bytes()).hexdigest())
        self.assertEqual(case["server_build_sha256"], hashlib.sha256(server.read_bytes()).hexdigest())
        self.assertEqual(case["log_sha256"], hashlib.sha256(
            (self.output / "session.log").read_bytes()).hexdigest())
        self.assertEqual(case["runner"], "athena-testlab/0.1.0")

    def test_case_without_binaries_is_not_fabricated(self):
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", "--manifest", str(self.manifest),
                         "--workspace", str(self.workspace), "--output", str(self.output)])
        self.assertEqual(code, 0)
        self.assertFalse((self.output / "cases").exists())

    def test_refuse_overwrite_reports(self):
        self.output.mkdir()
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace), "--output", str(self.output)])
        self.assertEqual(err.exception.code, 2)

    def test_report_cannot_be_inside_workspace(self):
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace),
                      "--output", str(self.workspace / "output")])
        self.assertEqual(err.exception.code, 2)

    def test_evidence_hash_size_limit(self):
        binary = self.workspace / "large.exe"
        binary.write_bytes(b"a" * 64)
        from athenatestlab import evidence
        with patch.object(evidence, "MAX_BIN_BYTES", 16):
            with self.assertRaises(ManifestError):
                file_sha(binary)

    def test_invalid_source_url_rejected_before_execution(self):
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace), "--output", str(self.output),
                      "--source-url", "http://localhost/private"])
        self.assertEqual(err.exception.code, 2)

    def test_no_raw_console_output_in_logs(self):
        port, _ = self.server(bytes.fromhex("ca11"))
        self.suite([self.tcp("tcp-exchange", port, send_hex="deadbeef",
                             expect_hex="ca11")])
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", "--manifest", str(self.manifest),
                         "--workspace", str(self.workspace), "--output", str(self.output)])
        self.assertEqual(code, 0)
        rendered = (self.output / "session.log").read_text()
        self.assertNotIn("deadbeef", rendered)
        self.assertNotIn("ca11", rendered)

    def test_process_expected_nonzero_exit_is_reported_accurately(self):
        test = {"id": "process-exit-7", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["-c", "import sys;sys.exit(7)"],
                "expect_exit": 7, "timeout_ms": 3000}
        result = execute(test, Path(sys.executable).parent, allow_exec=True)
        self.assertEqual(result["exit_code"], 7)
        self.assertTrue(result["passed"])
        self.assertEqual(result["observation"], "expected-exit-observed")

    def test_process_nonzero_unexpected_exit_fails(self):
        test = {"id": "process-exit-9", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["-c", "import sys;sys.exit(9)"],
                "expect_exit": 0, "timeout_ms": 3000}
        result = execute(test, Path(sys.executable).parent, allow_exec=True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["observation"], "unexpected-exit")

    def test_process_output_limit_enforced_without_disclosing_output(self):
        from athenatestlab import runner
        test = {"id": "large-output", "kind": "process-exit",
                "executable": Path(sys.executable).name,
                "args": ["-c", "import sys;sys.stdout.write('S' * 100000)"],
                "expect_exit": 0, "timeout_ms": 5000}
        with patch.object(runner, "MAX_PROCESS_OUTPUT", 20000):
            result = execute(test, Path(sys.executable).parent, allow_exec=True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["observation"], "output-limit")
        self.assertNotIn("SSSSSS", repr(result))

    def test_manifest_fuzz_untrusted_json_types_fail_cleanly(self):
        for kind in (None, {}, [], 17, True, ["tcp-open"]):
            self.suite([self.tcp("tcp-open", 6900) | {"kind": kind}])
            with self.subTest(kind=kind):
                with self.assertRaises(ManifestError):
                    load_manifest(self.manifest)
        for host in (None, {}, [], 17, True, ["127.0.0.1"]):
            self.suite([self.tcp("tcp-open", 6900) | {"host": host}])
            with self.subTest(host=host):
                with self.assertRaises(ManifestError):
                    load_manifest(self.manifest)

    def test_reject_unbounded_or_invalid_tcp_hex(self):
        for send_hex in ("z123", "a", "aa" * 257, 11, []):
            self.suite([self.tcp("tcp-exchange", 6900, send_hex=send_hex,
                                 expect_hex="bb")])
            with self.assertRaises(ManifestError):
                load_manifest(self.manifest)

    def test_reject_case_output_when_only_one_exe_specified(self):
        port, _ = self.server()
        self.suite([self.tcp("tcp-open", port)])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace), "--output", str(self.output),
                      "--client-exe", "Ragexe.exe"])
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_unauthorized_process_cannot_produce_successful_report(self):
        self.suite([{"id": "process-test", "kind": "process-exit",
                     "executable": "malicious.exe", "args": [],
                     "expect_exit": 0, "timeout_ms": 500}])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(["run", "--manifest", str(self.manifest),
                      "--workspace", str(self.workspace), "--output", str(self.output)])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
