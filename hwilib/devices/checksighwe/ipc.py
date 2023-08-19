"""IPC functions."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket

SIGN_TX = "SIGN_TX"
SIGN_MSG = "SIGN_MSG"
RESPONSE = "RESPONSE"
FNGRPRNT = "FNGRPRNT"
STOP = "STOP"
GET_XPUB = "GET_XPUB"
IpcMessage = tuple[str, str]


@dataclass
class PortSettings:
    """Class for port management."""

    first_port: int = 4444
    port_range: int = 100
    last_used_port = 4443


def ipc_connect(port: int) -> socket:
    """Connect to the service wallet.

    Args:
        port (int): _description_

    Raises:
        DeviceConnectionError: _description_

    Returns:
        socket: _description_
    """
    conn_sock = socket(AF_INET, SOCK_STREAM)
    if os.name == "nt":  # pragma: no cover
        # very short timeout for connection_socket
        # to enumerate very fast (especially on Windows)
        conn_sock.settimeout(1)
        conn_sock.connect(("127.0.0.1", port))
        # If connection_socket succeeded remove the timeout
        conn_sock.settimeout(None)
    else:
        conn_sock.connect(("127.0.0.1", port))
    return conn_sock


HostPortAddress = tuple[str, int]


def ipc_bind_listen() -> tuple[tuple[str, int], socket]:
    """Return a listening socket."""
    listening_socket = socket(AF_INET, SOCK_STREAM)
    if os.name != "nt":
        # Do not reuseaddress otherwise processes will listen on the same socket
        listening_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Look for a free port in the range to bind the listening_socket to
    min_port = PortSettings.last_used_port + 1
    max_port = PortSettings.first_port + PortSettings.port_range
    host_port = "127.0.0.1", max_port  # just to make Pylance happy
    for port in range(min_port, max_port):
        host_port = "127.0.0.1", port
        with contextlib.suppress(OSError):
            listening_socket.bind(host_port)
            listening_socket.listen(1)
            break
    if host_port[1] == max_port:
        raise RuntimeError("exausted ports")  # pragma: no cover
    PortSettings.last_used_port = host_port[1]
    return host_port, listening_socket


def ipc_recv(conn_sock: socket) -> IpcMessage:
    """Read an IPC message from the socket.

    IPC messages are in TLV format:
    [type: 8 bytes | payload_size: 8 bytes | payload: payload_size bytes]
    The payload is always as text

    Args:
        sock (socket.socket): _description_

    Returns:
        IpcMessage: _description_
    """
    type_and_payload_size = conn_sock.recv(16).decode("utf-8")
    cmd = type_and_payload_size[:8].strip()
    payload_size = int(type_and_payload_size[8:].strip())

    data = b""
    while payload_size:
        data_ = conn_sock.recv(min(payload_size, 2**15))
        payload_size -= len(data_)
        data += data_

    return cmd, data.decode("utf-8")


def ipc_sendall(conn_sock: socket, msg: IpcMessage) -> None:
    """Send an IPC message through the socket.

    IPC messages are in TLV format:
    [type: 8 bytes | payload_size: 8 bytes | payload: payload_size bytes]
    The payload is always as text

    Args:
        sock (socket.socket): _description_
        msg (IpcMessage): _description_

    Returns:
        bool: _description_
    """
    text = msg[0].ljust(8) + str(len(msg[1])).ljust(8) + msg[1]
    conn_sock.sendall(text.encode("utf-8"))
