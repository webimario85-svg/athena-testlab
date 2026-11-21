"""Strict, intentionally narrow rAthena login packet observations.

Only valid for an operator-controlled, isolated loopback login server.
Never emits credentials, session tokens, account names or wire payloads.
A synthetic login exchange is not validation of a real Ragexe client build.
"""
import os
import secrets
import socket
import struct

PACKET_CA_LOGIN = 0x0064
PACKET_AC_REFUSE_LOGIN = 0x083E
PACKET_AC_REFUSE_LOGIN_LEGACY = 0x006A
PACKET_AC_ACCEPT_LOGIN = 0x0069

def _fixed24(value: str) -> bytes:
    raw = value.encode("ascii", errors="strict")
    if not 1 <= len(raw) <= 23 or b"\x00" in raw:
        raise ValueError("invalid bounded account input")
    return raw.ljust(24, b"\x00")

def _recv(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        fragment = sock.recv(count - len(result))
        if not fragment:
            break
        result.extend(fragment)
    return bytes(result)

def attempt(test: dict) -> dict:
    """Actually send packet 0x0064; require a semantically relevant response.

    'account-rejected' expects a genuine unregistered-account refusal (error 0).
    'accepted' reads credentials from environment only, never manifest or CLI.
    """
    expect = test["expect"]
    if test.get("host") not in ("127.0.0.1", "::1"):
        return {"passed": False, "observation": "non-loopback-login-probe-blocked"}
    if expect not in ("accepted", "account-rejected"):
        return {"passed": False, "observation": "invalid-login-expectation"}
    if type(test.get("client_version")) is not int or not 20000101 <= test["client_version"] <= 20991231:
        return {"passed": False, "observation": "invalid-client-version-hint"}
    if expect == "accepted":
        username = os.environ.get("ATHENA_TESTLAB_LOGIN_USER", "")
        password = os.environ.get("ATHENA_TESTLAB_LOGIN_PASSWORD", "")
        if not username or not password:
            return {"passed": False, "observation": "login-credentials-not-configured"}
        try:
            user, secret = _fixed24(username), _fixed24(password)
        except (UnicodeError, ValueError):
            return {"passed": False, "observation": "invalid-login-credentials"}
    else:
        # Unique non-registering identity. No _M/_F suffix that can trigger
        # rAthena account auto-creation. No user-supplied credentials involved.
        user = _fixed24("atl" + secrets.token_hex(7))
        secret = _fixed24(secrets.token_hex(10))
    request = struct.pack("<HI24s24sB", PACKET_CA_LOGIN,
                          test["client_version"], user, secret, 0)
    assert len(request) == 55
    # Do not preserve credentials in application state or any evidence output.
    try:
        with socket.create_connection((test["host"], test["port"]),
                                      timeout=test["timeout_ms"]/1000) as conn:
            conn.settimeout(test["timeout_ms"]/1000)
            conn.sendall(request)
            header = _recv(conn, 2)
            if len(header) != 2:
                return {"passed": False, "observation": "login-response-absent"}
            opcode = struct.unpack("<H", header)[0]
            if opcode == PACKET_AC_REFUSE_LOGIN:
                body = _recv(conn, 4)
                if len(body) != 4:
                    return {"passed": False, "observation": "login-refusal-truncated"}
                error = struct.unpack("<I", body)[0]
                return {
                    "passed": expect == "account-rejected" and error == 0,
                    "observation": ("account-rejection-confirmed" if
                                    error == 0 else "login-refusal-other"),
                    "reply_opcode": "0x083e", "error_code": error,
                    "protocol_version_hint": test["client_version"],
                }
            if opcode == PACKET_AC_REFUSE_LOGIN_LEGACY:
                body = _recv(conn, 1)
                if len(body) != 1:
                    return {"passed": False, "observation": "login-refusal-truncated"}
                error = body[0]
                return {
                    "passed": expect == "account-rejected" and error == 0,
                    "observation": ("account-rejection-confirmed" if
                                    error == 0 else "login-refusal-other"),
                    "reply_opcode": "0x006a", "error_code": error,
                    "protocol_version_hint": test["client_version"],
                }
            if opcode == PACKET_AC_ACCEPT_LOGIN:
                length = _recv(conn, 2)
                if len(length) != 2:
                    return {"passed": False, "observation": "login-accept-truncated"}
                packet_len = struct.unpack("<H", length)[0]
                # Do not read tokens or authenticated session contents.
                return {
                    "passed": expect == "accepted" and 16 <= packet_len <= 8192,
                    "observation": ("login-accept-packet-observed" if
                                    16 <= packet_len <= 8192 else "login-accept-length-invalid"),
                    "reply_opcode": "0x0069",
                    "protocol_version_hint": test["client_version"],
                }
            return {"passed": False, "observation": "unexpected-login-reply",
                    "reply_opcode": f"0x{opcode:04x}"}
    except (OSError, TimeoutError):
        return {"passed": False, "observation": "login-server-unavailable"}
