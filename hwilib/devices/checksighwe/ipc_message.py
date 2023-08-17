"""IpcMessage class.
"""

from __future__ import annotations

SIGN_TX = "sgtx"
SIGN_MESSAGE = "sgms"
RESP = "resp"
PING = "ping"
EXIT = "exit"
XPUB = "xpub"
ECDSA_SIGN = "dsas"


class IpcMessage:
    """Class that represents an ipc message.

    An ipc message is command with a raw data payload.
    For serialization the data payload is always a string,
    so use base64 encoding for binary data
    """

    def __init__(self, cmd: str, data: str):
        self.cmd = cmd
        self.data = data

    @staticmethod
    def cmd_msg_size() -> int:
        """_summary_

        Returns:
            int: _description_
        """
        return 4

    @staticmethod
    def get_size_msg_size() -> int:
        """_summary_

        Returns:
            int: _description_
        """
        return 8
