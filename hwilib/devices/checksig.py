"""
CheckSig HWE Devices
************************
"""

from __future__ import annotations

import base64
from typing import Any

from hwilib._base58 import xpub_main_2_test
from hwilib.common import Chain
from hwilib.key import ExtendedKey
from hwilib.psbt import PSBT

from ..hwwclient import HardwareWalletClient
from .checksighwe import __version__
from .checksighwe.ipc import (
    GET_XPUB,
    SIGN_MSG,
    SIGN_TX,
    enum_port_fingerprint,
    ipc_connect,
    ipc_recv,
    ipc_sendall,
)


class ChecksigClient(HardwareWalletClient):
    """Extend the HardwareWalletClient for CheckSig HWE."""

    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        # Used to know where to connect for this device
        self.port = int(path.split(":")[1])
        self.host = path.split(":")[0]

    # Segwit V0 only
    def sign_tx(self, psbt: PSBT) -> PSBT:
        conn_sock = ipc_connect((self.host, self.port))
        data = psbt.serialize() + "\n"
        ipc_sendall(conn_sock, (SIGN_TX, data))
        response = ipc_recv(conn_sock, check_response=True)
        psbt = PSBT()
        psbt.deserialize(response[1])
        return psbt

    def sign_message(self, message: str | bytes, bip32_path: str) -> str:
        if isinstance(message, str):
            message = message.encode()
        conn_sock = ipc_connect((self.host, self.port))
        message_b64 = base64.b64encode(message).decode("utf-8")
        data = message_b64 + "\n" + bip32_path
        ipc_sendall(conn_sock, (SIGN_MSG, data))
        response = ipc_recv(conn_sock, check_response=True)
        return base64.b64decode(response[1]).decode()

    def close(self) -> None:
        pass

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        conn_sock = ipc_connect((self.host, self.port))
        data = bip32_path + "\n"
        ipc_sendall(conn_sock, (GET_XPUB, data))
        response = ipc_recv(conn_sock, check_response=True)
        xpub = base64.b64decode(response[1]).decode("utf-8")
        if self.chain != Chain.MAIN:
            xpub = xpub_main_2_test(xpub)
        return ExtendedKey.deserialize(xpub)

    def wipe_device(self) -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def setup_device(self, _: str = "", __: str = "") -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def restore_device(self, _: str = "", __: int = 24) -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def backup_device(self, _: str = "", __: str = "") -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")


def enumerate(  # pylint: disable=redefined-builtin
    _: str, __: bool, ___: Chain
) -> list[dict[str, Any]]:
    """Return a list of CheckSig HWEs."""
    return [
        {
            "type": "checksig",
            "model": f"hwe {__version__}",
            "path": f"127.0.0.1:{str(port)}",
            "needs_pin_sent": False,
            "needs_passphrase_sent": False,
            "fingerprint": fingerprint,
        }
        for port, fingerprint in enum_port_fingerprint()
    ]
