"""Small text helpers shared by the checkers."""

import re
from typing import FrozenSet, List, Optional

_LEADING_ADDR = re.compile(r"^\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})\s*:?\s+(.*)$", re.S)
_HEX = re.compile(r"(?<![\w])-?0[xX][0-9a-fA-F]+")
_DEC = re.compile(r"(?<![\w.])-?\d+(?!\w)")
_MASK32, _MASK64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


def compact(text: Optional[str]) -> str:
    """Lower-case with all whitespace removed (tolerates formatting differences)."""
    return re.sub(r"\s+", "", text or "").lower()


def strip_leading_address(quote: str, address: Optional[str]) -> str:
    """Drop a leading '0x00401000  ' if it is the evidence's own address."""
    q = quote.strip()
    m = _LEADING_ADDR.match(q)
    if m and address:
        try:
            if int(m.group(1), 16) == int(address.split("0x", 1)[1], 16):
                return m.group(2).strip()
        except (ValueError, IndexError):
            pass
    return q


def split_elisions(quote: str) -> List[str]:
    parts = re.split(r"\.\.\.|\u2026", quote)
    return [p.strip() for p in parts if p.strip()]


def extract_numbers(text: str) -> List[int]:
    values = []
    for m in _HEX.finditer(text):
        values.append(int(m.group(0), 16))
    rest = _HEX.sub(" ", text)
    for m in _DEC.finditer(rest):
        values.append(int(m.group(0)))
    return values


def number_keys(value: int) -> FrozenSet[int]:
    """Equivalent forms of a number so -1, 0xffffffff and 1 can be compared leniently."""
    return frozenset({abs(value), value & _MASK32, value & _MASK64})


def number_in(value: int, pool: FrozenSet[int]) -> bool:
    return bool(number_keys(value) & pool)
