"""Setting for CheckSig HWE."""

from dataclasses import dataclass


@dataclass
class Settings:
    """Class for port management."""

    first_port: int = 4444
    port_range: int = 100
    last_used_port = 4443
