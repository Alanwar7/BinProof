"""One canonical address format, shared by the extractor and the loader.

The extractor writes "0x%08x" (e.g. 0x00401000) and "EXTERNAL:0x%x" for
addresses in Ghidra's external space. Users will type 401000, 0x401000 or an
int, so every public lookup normalizes through here first.

Strings are always hex ("10" means 0x10). ints are plain numbers.
"""

from __future__ import annotations

import re
from typing import Union

from .errors import InvalidAddressError

EXTERNAL_PREFIX = "EXTERNAL:"
_HEX = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{1,16})$")
_MAX = 0xFFFFFFFFFFFFFFFF

AddressLike = Union[str, int]


def normalize_address(value: AddressLike) -> str:
    """Return the canonical text form of an address or raise InvalidAddressError."""
    if isinstance(value, bool):
        raise InvalidAddressError("not an address: %r" % (value,))
    if isinstance(value, int):
        if not 0 <= value <= _MAX:
            raise InvalidAddressError("address out of range: %r" % (value,))
        return "0x%08x" % value
    if not isinstance(value, str):
        raise InvalidAddressError("not an address: %r" % (value,))

    text = value.strip()
    external = text.upper().startswith(EXTERNAL_PREFIX)
    if external:
        text = text[len(EXTERNAL_PREFIX):].strip()
    match = _HEX.match(text)
    if not match:
        raise InvalidAddressError("not an address: %r" % (value,))
    number = int(match.group(1), 16)
    return ("EXTERNAL:0x%x" % number) if external else ("0x%08x" % number)


def is_external(address: str) -> bool:
    return address.startswith(EXTERNAL_PREFIX)


def address_to_int(address: AddressLike) -> int:
    return int(normalize_address(address).split("0x", 1)[1], 16)
