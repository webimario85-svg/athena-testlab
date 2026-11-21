"""M6 authentication packet probe regression tests.

All mock listeners are synthetic; none validates a real client session.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from athenatestlab.cli import main
from athenatestlab.manifest import ManifestError, load_manifest
from athenatestlab.protocol import attempt, PACKET_CA_LOGIN
from athenatestlab.runner import execute


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.doc = self.base / "manifest.json"
        self.output = self.base / "out"

    def fake_server(self, response: bytes):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        received = []

        def serve():
            try:
                listener.settimeout(3)
                client, _ = listener.accept()
                with client:
                    client.settimeout(2)
                    remaining = 55
                    body = b""
                    while remaining:
                        chunk = client.recv(remaining)
                        if not chunk:
                            break
                        body += chunk
                        remaining -= len(chunk)
                    received.append(body)
                    client.sendall(response)
            except OSError:
                pass
            finally:
                listener.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.addCleanup(t.join, 3)
        return port, received

    @staticmethod
    def probe(port, expect="account-rejected"):
        return {
            "id": "rathena-login-test", "kind": "rathena-login",
            "host": "127.0.0.1", "port": port,
            "client_version": 20211103,
            "expect": expect, "timeout_ms": 1000,
        }

    def write(self, test):
        self.doc.write_text(json.dumps({
            "schema_version": "1", "suite_id": "m6-protocol", "tests": [test]
        }), encoding="utf-8")

    def test_reject_response_is_real_packet_not_just_open_socket(self):
        port, received = self.fake_server(struct.pack("<HI", 0x083E, 0))
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["observation"], "account-rejection-confirmed")
        self.assertEqual(result["reply_opcode"], "0x083e")
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(len(received[0]), 55)
        self.assertEqual(struct.unpack("<H", received[0][:2])[0], PACKET_CA_LOGIN)
        self.assertNotIn("atl", repr(result))

    def test_modern_refusal_error_one_is_not_success(self):
        port, _ = self.fake_server(struct.pack("<HI", 0x083E, 1))
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["observation"], "login-refusal-other")

    def test_legacy_refusal_supported(self):
        port, _ = self.fake_server(struct.pack("<HB", 0x006A, 0))
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertTrue(result["passed"])
        self.assertEqual(result["reply_opcode"], "0x006a")

    def test_random_socket_bytes_are_not_a_valid_login(self):
        port, _ = self.fake_server(b"\xfe\xca\x00\x00")
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["observation"], "unexpected-login-reply")

    def test_no_reply_is_not_a_protocol_success(self):
        port, _ = self.fake_server(b"")
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertFalse(result["passed"])

    def test_login_probe_cannot_run_without_explicit_permission(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")):
            result = execute(self.probe(6900), self.workspace, allow_exec=False)
        self.assertEqual(result["observation"], "login-probe-not-authorized")

    def test_accepted_response_requires_env_credentials(self):
        port, received = self.fake_server(struct.pack("<HH", 0x0069, 55))
        with patch.dict(os.environ, {"ATHENA_TESTLAB_LOGIN_USER": "labuser",
                                     "ATHENA_TESTLAB_LOGIN_PASSWORD": "labsafe1"}):
            result = execute(self.probe(port, "accepted"), self.workspace,
                             allow_exec=False, allow_login_probe=True)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["observation"], "login-accept-packet-observed")
        self.assertEqual(received[0][6:13], b"labuser")
        self.assertNotIn("labuser", repr(result))
        self.assertNotIn("labsafe1", repr(result))

    def test_without_env_credentials_fail_before_any_network(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            result = attempt(self.probe(6900, "accepted"))
        self.assertEqual(result["observation"], "login-credentials-not-configured")

    def test_accepted_response_is_not_success_for_negative_scenario(self):
        port, _ = self.fake_server(struct.pack("<HH", 0x0069, 55))
        result = execute(self.probe(port), self.workspace, allow_exec=False,
                         allow_login_probe=True)
        self.assertFalse(result["passed"])

    def test_refusal_not_success_for_accepted_scenario(self):
        port, _ = self.fake_server(struct.pack("<HI", 0x083E, 0))
        with patch.dict(os.environ, {"ATHENA_TESTLAB_LOGIN_USER": "tester",
                                     "ATHENA_TESTLAB_LOGIN_PASSWORD": "testpass"}):
            result = execute(self.probe(port, "accepted"), self.workspace,
                             allow_exec=False, allow_login_probe=True)
        self.assertFalse(result["passed"])

    def test_manifest_rejects_external_login_hosts_and_secret_fields(self):
        for changes in ({"host": "example.com"}, {"host": "8.8.8.8"},
                        {"password": "not-allowed"}, {"client_version": True},
                        {"expect": ["accepted"]}, {"client_version": 999},
                        {"timeout_ms": False}):
            test = self.probe(6900) | changes
            self.write(test)
            with self.subTest(changes=changes):
                with self.assertRaises(ManifestError):
                    load_manifest(self.doc)

    def test_cli_requires_login_authorization_flag(self):
        self.write(self.probe(6900))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["run", "--manifest", str(self.doc),
                      "--workspace", str(self.workspace), "--output",
                      str(self.output)])
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_direct_probe_blocks_external_hosts(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")):
            bad = attempt(self.probe(6900) | {"host": "198.51.100.10"})
        self.assertFalse(bad["passed"])
        self.assertEqual(bad["observation"], "non-loopback-login-probe-blocked")

    def test_direct_probe_rejects_untrusted_version_value(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")):
            bad = attempt(self.probe(6900) | {"client_version": True})
        self.assertFalse(bad["passed"])
        self.assertEqual(bad["observation"], "invalid-client-version-hint")

    def test_real_packet_scenario_is_precisely_named_in_export(self):
        port, _ = self.fake_server(struct.pack("<HI", 0x083E, 0))
        self.write(self.probe(port))
        (self.workspace / "Ragexe.exe").write_bytes(b"MZsynthetic-client")
        (self.workspace / "map-server").write_bytes(b"synthetic-server")
        with contextlib.redirect_stdout(io.StringIO()):
            exitcode = main(["run", "--manifest", str(self.doc),
                             "--workspace", str(self.workspace), "--output",
                             str(self.output), "--allow-login-probe",
                             "--client-exe", "Ragexe.exe", "--server-exe", "map-server"])
        self.assertEqual(exitcode, 0)
        exported = list((self.output / "cases").glob("*.json"))
        self.assertEqual(len(exported), 1)
        case = json.loads(exported[0].read_text("utf-8"))
        self.assertEqual(case["scenario"], "rathena-account-rejected")
        self.assertEqual(case["status"], "pass")
        self.assertNotIn("username", json.dumps(case))
        self.assertNotIn("password", json.dumps(case))

    def test_cli_packet_test_sanitizes_log_and_evidence(self):
        port, received = self.fake_server(struct.pack("<HI", 0x083E, 0))
        self.write(self.probe(port))
        with contextlib.redirect_stdout(io.StringIO()):
            exitcode = main(["run", "--manifest", str(self.doc),
                             "--workspace", str(self.workspace), "--output",
                             str(self.output), "--allow-login-probe"])
        self.assertEqual(exitcode, 0)
        record = json.loads((self.output / "run.json").read_text("utf-8"))
        result = record["tests"][0]
        self.assertEqual(result["observation"], "account-rejection-confirmed")
        log = (self.output / "session.log").read_text("utf-8")
        self.assertNotIn("atl", log)
        self.assertNotIn("password", log)
        self.assertEqual(len(received[0]), 55)


if __name__ == "__main__":
    unittest.main()
