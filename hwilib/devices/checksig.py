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
from .checksighwe.ipc import ipc_connect, ipc_send_read
from .checksighwe.ipc_message import PING, SIGN_MESSAGE, SIGN_TX, XPUB
from .checksighwe.settings import Settings


class ChecksigClient(HardwareWalletClient):
    """Extend the HardwareWalletClient for CheckSig HWE."""

    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        # Used to know where to connect for this device
        self.port = int(path.split(":")[1])

    # Segwit V0 only
    def sign_tx(self, psbt: PSBT) -> PSBT:
        sock = ipc_connect(self.port)
        data = psbt.serialize() + "\n"
        response = ipc_send_read(sock, SIGN_TX, data)
        psbt = PSBT()
        psbt.deserialize(response.data)
        return psbt

    def sign_message(self, message: str | bytes, bip32_path: str) -> str:
        if isinstance(message, str):
            message = message.encode()
        sock = ipc_connect(self.port)
        message_b64 = base64.b64encode(message).decode("utf-8")
        data = message_b64 + "\n" + bip32_path
        response = ipc_send_read(sock, SIGN_MESSAGE, data)
        return base64.b64decode(response.data).decode()

    def close(self) -> None:
        pass

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        sock = ipc_connect(self.port)
        data = bip32_path + "\n"
        response = ipc_send_read(sock, XPUB, data)
        xpub = base64.b64decode(response.data).decode("utf-8")
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
    _: str = "", __: bool = False, ___: Chain = Chain.MAIN
) -> list[dict[str, Any]]:
    """Return a list of CheckSig HWEs."""
    devices = []
    for i in range(Settings.port_range):
        port = Settings.first_port + i
        sock = ipc_connect(port)
        response = ipc_send_read(sock, PING, "")
        device = {
            "type": "checksig",
            "model": "checksig_hwe",
            "path": f"127.0.0.1:{str(port)}",
            "needs_pin_sent": False,
            "needs_passphrase_sent": False,
            "fingerprint": response.data,
        }
        devices.append(device)
        sock.close()
    return devices
