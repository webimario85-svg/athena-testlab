"""Real OS-level probes with explicit trust boundaries.

No shell invocation; loopback only; process execution requires operator opt-in.
No raw binary output, TCP payload or exception text in public evidence logs.
"""
import hashlib
from pathlib import Path
import socket
import subprocess
import threading
import time

from .manifest import inside_workspace

MAX_PROCESS_OUTPUT = 2 * 1024 * 1024


def _process(test: dict, root: Path, allow_exec: bool) -> dict:
    if not allow_exec:
        return {"passed": False, "observation": "execution-not-authorized",
                "output_bytes": 0}
    exe = inside_workspace(root, test["executable"])
    if not exe.is_file():
        return {"passed": False, "observation": "executable-not-found",
                "output_bytes": 0}
    # Not a shell command. Exact executable file in user-designated workspace.
    argv = [str(exe), *test["args"]]
    deadline = test["timeout_ms"] / 1000
    data_digest = hashlib.sha256()
    total = 0
    excessive = False
    try:
        proc = subprocess.Popen(argv, cwd=str(root), shell=False,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except OSError:
        return {"passed": False, "observation": "process-start-failed",
                "output_bytes": 0}

    def consume():
        nonlocal total, excessive
        try:
            assert proc.stdout is not None
            while True:
                block = proc.stdout.read(8192)
                if not block:
                    break
                total += len(block)
                if total > MAX_PROCESS_OUTPUT:
                    excessive = True
                    proc.kill()
                    break
                data_digest.update(block)
        except OSError:
            pass

    reader = threading.Thread(target=consume, daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=deadline)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
    finally:
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        reader.join(timeout=3)
        if proc.stdout:
            proc.stdout.close()
    if timed_out:
        state = "process-timeout"
    elif excessive:
        state = "output-limit"
    elif proc.returncode == test["expect_exit"]:
        state = "expected-exit-observed"
    else:
        state = "unexpected-exit"
    return {"passed": state == "expected-exit-observed",
            "observation": state, "exit_code": proc.returncode,
            "output_bytes": total if total <= MAX_PROCESS_OUTPUT else MAX_PROCESS_OUTPUT,
            "output_sha256": data_digest.hexdigest()}


def _tcp(test: dict) -> dict:
    host, port = test["host"], test["port"]
    deadline = test["timeout_ms"] / 1000
    try:
        with socket.create_connection((host, port), timeout=deadline) as sock:
            sock.settimeout(deadline)
            if test["kind"] == "tcp-open":
                return {"passed": True, "observation": "tcp-port-accepted"}
            packet = bytes.fromhex(test["send_hex"])
            expected = bytes.fromhex(test["expect_hex"])
            if packet:
                sock.sendall(packet)
            received = b""
            while len(received) < len(expected):
                piece = sock.recv(len(expected) - len(received))
                if not piece:
                    break
                received += piece
            matched = received == expected
            return {"passed": matched,
                    "observation": ("tcp-bytes-matched" if matched
                                    else "tcp-bytes-differed"),
                    "sent_bytes": len(packet), "received_bytes": len(received)}
    except (OSError, TimeoutError):
        return {"passed": False, "observation": "tcp-unavailable"}


def execute(test: dict, root: Path, *, allow_exec: bool) -> dict:
    start = time.monotonic()
    if test["kind"] == "process-exit":
        outcome = _process(test, root, allow_exec)
    else:
        outcome = _tcp(test)
    # A successful test never implies a Ragnarok protocol login.
    return {
        "id": test["id"], "kind": test["kind"],
        **outcome,
        "duration_ms": max(0, round((time.monotonic() - start) * 1000)),
    }
