"""IPC functions."""

from __future__ import annotations

import contextlib
import socket
from dataclasses import dataclass

SIGN_TX = "SIGN_TX"
SIGN_MSG = "SIGN_MSG"
RESPONSE = "RESPONSE"
FNGRPRNT = "FNGRPRNT"
STOP = "STOP"
GET_XPUB = "GET_XPUB"
# e.g., (GET_XPUB, "m/44h/0h/0h")
IpcMessage = tuple[str, str]
# e.g., ("127.0.0.1", 4444)
HostPortAddress = tuple[str, int]


@dataclass
class PortSettings:
    """Class for port management."""

    first_port: int = 4444
    next_port: int = 4444


def enum_port_fingerprint() -> list[tuple[int, str]]:
    """Return a list of HWE port, fingerprint tuples."""
    result: list[tuple[int, str]] = []
    for port in range(PortSettings.first_port, PortSettings.next_port):
        with contextlib.suppress(ConnectionRefusedError):
            with ipc_connect(("127.0.0.1", port)) as conn_sock:
                ipc_sendall(conn_sock, (FNGRPRNT, ""))
                response = ipc_recv(conn_sock, check_response=True)
            result.append((port, response[1]))
    return result


def ipc_connect(host_port: HostPortAddress) -> socket.socket:
    """Connect to the service wallet."""
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((host_port[0], host_port[1]))
    return conn_sock


def ipc_recv(conn_sock: socket.socket, check_response: bool = False) -> IpcMessage:
    """Read an IPC message from the socket."""
    # timeout_ = conn_sock.gettimeout()
    # conn_sock.settimeout(timeout)
    data = conn_sock.recv(16)
    # conn_sock.settimeout(timeout_)

    type_and_payload_size = data.decode("utf-8")
    if (cmd := type_and_payload_size[:8].strip()) != RESPONSE and check_response:
        raise RuntimeError(f"malformed response {cmd=}")  # pragma: no cover
    payload_size = int(type_and_payload_size[8:].strip())

    data = b""
    while to_be_received := payload_size - len(data):
        data += conn_sock.recv(min(to_be_received, 2**15))
    return cmd, data.decode("utf-8")


def ipc_sendall(conn_sock: socket.socket, msg: IpcMessage) -> None:
    """Send an IPC message through the socket."""
    text = msg[0].ljust(8) + str(len(msg[1])).ljust(8) + msg[1]
    conn_sock.sendall(text.encode("utf-8"))
