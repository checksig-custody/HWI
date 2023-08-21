"""HWI and IPC functions."""

from __future__ import annotations

import base64
import contextlib
import socket
from collections.abc import Callable

from hwilib._base58 import xpub_main_2_test
from hwilib.common import Chain
from hwilib.key import ExtendedKey
from hwilib.psbt import PSBT

FNGRPRNT = "FNGRPRNT"
GET_XPUB = "GET_XPUB"
SIGN_TX = "SIGN_TX"
SIGN_MSG = "SIGN_MSG"
RESPONSE = "RESPONSE"

# e.g., (GET_XPUB, "m/44h/0h/0h")
IpcMessage = tuple[str, str]


def enum_fingerprint_port(host: str = "127.0.0.1") -> list[tuple[str, int]]:
    """Return a list of HWE (fingerprint, port) tuples."""
    result: list[tuple[str, int]] = []
    for port in range(4444, 4544):
        with contextlib.suppress(ConnectionRefusedError, ConnectionResetError):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn_sock:
                conn_sock.connect((host, port))
                ipc_sendall(conn_sock, (FNGRPRNT, ""))
                response = ipc_recv(conn_sock, check_response=True)
            result.append((response[1], port))
    return result


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


def get_master_fingerprint(
    cmd_handler: Callable[[tuple[str, str]], tuple[str, str]],
) -> bytes:
    """Return the master public key fingerprint as bytes.

    To be used for the HardwareWalletClient interface implementation of
    ChecksigClient.
    """
    msg = FNGRPRNT, ""
    response = cmd_handler(msg)
    return response[1].encode("utf-8")


def get_pubkey_at_path(
    cmd_handler: Callable[[tuple[str, str]], tuple[str, str]],
    bip32_path: str,
    chain: Chain = Chain.MAIN,
) -> ExtendedKey:
    """Return the public key at the BIP 32 derivation path.

    To be used for the HardwareWalletClient interface implementation of
    ChecksigClient.
    """
    msg = GET_XPUB, bip32_path + "\n"
    response = cmd_handler(msg)
    xpub = base64.b64decode(response[1]).decode("utf-8")
    if chain != Chain.MAIN:
        xpub = xpub_main_2_test(xpub)
    return ExtendedKey.deserialize(xpub)


def sign_tx(
    cmd_handler: Callable[[tuple[str, str]], tuple[str, str]],
    psbt: PSBT | str,
) -> PSBT:  # Segwit V0 only
    """Sign a partially signed bitcoin transaction.

    Accept a HWI PSBT or a base64 psbt string as input. To be used for
    the HardwareWalletClient interface implementation of ChecksigClient.
    """
    data = psbt if isinstance(psbt, str) else psbt.serialize()
    msg = SIGN_TX, data + "\n"
    response = cmd_handler(msg)
    psbt = PSBT()
    psbt.deserialize(response[1])
    return psbt


def sign_message(
    cmd_handler: Callable[[tuple[str, str]], tuple[str, str]],
    message: str | bytes,
    bip32_path: str,
) -> str:
    """Sign a message (bitcoin message signing).

    To be used for the HardwareWalletClient interface implementation of
    ChecksigClient.
    """
    if isinstance(message, str):
        message = message.encode()
    message_b64 = base64.b64encode(message).decode("utf-8")
    msg = SIGN_MSG, message_b64 + "\n" + bip32_path
    response = cmd_handler(msg)
    return base64.b64decode(response[1]).decode()
