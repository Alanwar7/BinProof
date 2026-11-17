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


_BOILERPLATE = [re.compile(x) for x in (
    r"^(push|pop)(rbp|ebp|rbx|ebx|rsi|rdi|esi|edi|r1[2-5]d?)$",
    r"^mov(rbp,rsp|ebp,esp|rsp,rbp|esp,ebp)$",
    r"^(sub|add)(rsp|esp),(0x)?[0-9a-f]+$",
    r"^(leave|leaveq|ret|retn|retq|nop|endbr64|endbr32|hlt|int3)$",
    r"^ret[nq]?(0x)?[0-9a-f]+$",
    r"^nop.*$",
)]


def is_boilerplate_instruction(text: str) -> bool:
    """Prologue/epilogue/padding instructions say nothing about what a function does."""
    c = compact(text)
    return any(rx.match(c) for rx in _BOILERPLATE)


def identifier_like(token: str) -> bool:
    """Looks like a code identifier (camelCase, snake_case, digits, FUN_...), not an English word."""
    return ("_" in token or any(ch.isdigit() for ch in token) or bool(re.search(r"[a-z][A-Z]", token))
            or token.startswith("FUN_"))


def compact_with_map(text: str):
    """compact() plus, for each kept character, its offset in the original text."""
    chars, idx = [], []
    for i, ch in enumerate(text):
        if not ch.isspace():
            chars.append(ch.lower())
            idx.append(i)
    return "".join(chars), idx


def find_all(haystack: str, needle: str) -> List[int]:
    out, start = [], 0
    while needle:
        i = haystack.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + len(needle)
    return out


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
