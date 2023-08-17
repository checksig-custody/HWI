"""IPC functions."""

from __future__ import annotations

import contextlib
import os
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket

from hwilib.errors import ActionCanceledError, DeviceConnectionError

from .ipc_message import IpcMessage
from .settings import Settings

_DEVICE_CONNECTION_ERROR_MSG = "Unable to open a socket with the CheckSig HWE"


def ipc_connect(port: int) -> socket:
    """Connect to the service wallet.

    Args:
        port (int): _description_

    Raises:
        DeviceConnectionError: _description_

    Returns:
        socket: _description_
    """
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        if os.name == "nt":  # pragma: no cover
            # very short timeout for connection
            # to enumerate very fast (especially on Windows)
            sock.settimeout(1)
            sock.connect(("127.0.0.1", port))
            # If connection succeeded remove the timeout
            sock.settimeout(None)
        else:
            sock.connect(("127.0.0.1", port))
    except Exception as err:
        raise DeviceConnectionError(_DEVICE_CONNECTION_ERROR_MSG) from err
    return sock


def ipc_start() -> tuple[int, socket]:
    """Start the service wallet in listening mode."""
    # Create a socket
    sock = socket(AF_INET, SOCK_STREAM)
    # On windows don't use reuseaddress otherwise processes will listen on the same socket
    if os.name != "nt":
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Bind the socket to the port
    # Look for a free port on the range
    min_port = Settings.last_used_port + 1
    max_port = Settings.first_port + Settings.port_range
    port = 0  # just to make Pylance happy
    for port in range(min_port, max_port):
        with contextlib.suppress(OSError):
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
            break
    Settings.last_used_port = port
    return (port, sock)


def ipc_read(sock: socket) -> IpcMessage:  # pragma: no cover used by HWI
    """Read an IPC message from the socket.

    IPC messages are in TLV format:
    [type: 4 bytes | payload_size: 8 bytes | payload: payload_size bytes]
    The payload is always as text

    Args:
        sock (socket.socket): _description_

    Returns:
        IpcMessage | None: _description_
    """
    # get the type
    cmd = sock.recv(IpcMessage.cmd_msg_size()).decode("utf-8")
    cmd = cmd.strip().replace(" ", "")

    # get the size
    size = sock.recv(IpcMessage.get_size_msg_size()).decode("utf-8")
    size = size.strip().replace(" ", "")

    if len(size) == 0:
        raise RuntimeError("unexpected error")

    # read the payload
    int_size = int(size)
    value = b""
    while int_size:
        data = sock.recv(min(int_size, 2**15))
        int_size -= len(data)
        value += data

    return IpcMessage(cmd, str(value.decode("utf-8")))


def ipc_send(sock: socket, msg: IpcMessage) -> None:
    """Send an IPC message through the socket.

    IPC messages are in TLV format:
    [type: 4 bytes | payload_size: 8 bytes | payload: payload_size bytes]
    The payload is always as text

    Args:
        sock (socket.socket): _description_
        msg (IpcMessage): _description_

    Returns:
        bool: _description_
    """
    # serialize the type
    cmd = msg.cmd.ljust(IpcMessage.cmd_msg_size())

    # serialize the size
    size = len(msg.data)
    str_size = str(size).ljust(IpcMessage.get_size_msg_size())

    # serialize the payload and send all
    complete = cmd + str_size + msg.data
    sock.sendall(str.encode(complete))


def ipc_send_read(
    sock: socket, cmd: str, data: str
) -> IpcMessage:  # pragma: no cover used by HWI
    """Send an IPC message and read the response.

    Args:
        sock (socket): _description_
        cmd (str): _description_
        data (str): _description_

    Raises:
        ActionCanceledError: _description_

    Returns:
        IpcMessage: _description_
    """
    try:
        ipc_send(sock, IpcMessage(cmd, data))
        response = ipc_read(sock)
    except Exception as err:
        err_msg = f"CheckSig HWE error {cmd=} {data=} {sock=}"
        raise ActionCanceledError(err_msg) from err
    return response
