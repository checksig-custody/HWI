"""
CheckSig HWE Devices
************************
"""

from __future__ import annotations

import socket
from typing import Any

from hwilib.common import Chain
from hwilib.key import ExtendedKey
from hwilib.psbt import PSBT

from ..hwwclient import HardwareWalletClient
from .checksighwe import __version__, ipc


class ChecksigClient(HardwareWalletClient):
    """Extend the HardwareWalletClient for CheckSig HWE."""

    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        # Used to know where to connect for this device
        self.port = int(path.split(":")[1])
        self.host = path.split(":")[0]

    def get_master_fingerprint(self) -> bytes:
        return ipc.get_master_fingerprint(self._cmd_handler)

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        return ipc.get_pubkey_at_path(self._cmd_handler, bip32_path, self.chain)

    def sign_tx(self, psbt: PSBT) -> PSBT:  # Segwit V0 only
        return ipc.sign_tx(self._cmd_handler, psbt)

    def sign_message(self, message: str | bytes, bip32_path: str) -> str:
        return ipc.sign_message(self._cmd_handler, message, bip32_path)

    def wipe_device(self) -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def setup_device(self, _: str = "", __: str = "") -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def restore_device(self, _: str = "", __: int = 24) -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def backup_device(self, _: str = "", __: str = "") -> bool:
        raise NotImplementedError("CheckSig HWE does not implement this method")

    def close(self) -> None:
        pass

    def _cmd_handler(self, msg: ipc.IpcMessage) -> ipc.IpcMessage:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn_sock:
            conn_sock.connect((self.host, self.port))
            ipc.ipc_sendall(conn_sock, msg)
            return ipc.ipc_recv(conn_sock, check_response=True)


def enumerate(  # pylint: disable=redefined-builtin
    _: str, __: bool, ___: Chain
) -> list[dict[str, Any]]:
    """Return a list of CheckSig HWEs."""
    return [
        {
            "type": "checksig",
            "model": f"hwe {__version__}",
            "path": f"{ipc.HOST}:{str(port)}",
            "needs_pin_sent": False,
            "needs_passphrase_sent": False,
            "fingerprint": fingerprint,
        }
        for fingerprint, port in ipc.enum_fingerprint_port()
    ]
