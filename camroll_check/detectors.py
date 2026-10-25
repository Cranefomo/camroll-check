"""Detectors for sensitive text found in photos/screenshots.

Every detector returns a list of Finding. Raw secrets never leave this module:
`masked` is the only value that gets printed or written to the report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HIGH, MEDIUM, LOW = "high", "medium", "low"

_BIP39 = set(
    (Path(__file__).parent / "bip39_english.txt").read_text().split()
)


@dataclass
class Finding:
    kind: str
    severity: str
    masked: str
    note: str = ""
    extra: dict = field(default_factory=dict)


def _mask(s: str, keep_start: int = 2, keep_end: int = 2) -> str:
    s = s.strip()
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    stars = min(8, len(s) - keep_start - keep_end)
    return s[:keep_start] + "*" * stars + s[-keep_end:]


# ---------- seed phrases (BIP39) ----------

def find_seed_phrases(text: str) -> list[Finding]:
    # drop numbering like "1." "12)" and punctuation, keep word order
    tokens = re.findall(r"[a-zA-Z]+", text.lower())
    best, run = 0, 0
    for t in tokens:
        if t in _BIP39:
            run += 1
            best = max(best, run)
        else:
            run = 0
    if best >= 12:
        return [Finding("seed_phrase", HIGH, "12+ BIP39 words in a row",
                        "looks like a crypto wallet recovery phrase")]
    return []


# ---------- payment cards (Luhn) ----------

def _luhn(num: str) -> bool:
    total, alt = 0, False
    for d in reversed(num):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def find_cards(text: str) -> list[Finding]:
    out = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and digits[0] in "23456" and _luhn(digits):
            out.append(Finding("payment_card", HIGH,
                               f"{digits[0]}*** **** **** {digits[-4:]}",
                               "Luhn-valid card number"))
    if out and re.search(r"\b(cvv|cvc|cvv2|security code)\b", text, re.I):
        out[0].note += ", CVV label on the same image"
    return out


# ---------- IBAN (mod 97) ----------

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")


def _iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


def find_ibans(text: str) -> list[Finding]:
    out = []
    for m in _IBAN_RE.finditer(text.upper()):
        iban = m.group().replace(" ", "")
        if 15 <= len(iban) <= 34 and _iban_ok(iban):
            out.append(Finding("iban", MEDIUM, iban[:4] + " **** " + iban[-4:],
                               "valid IBAN"))
    return out


# ---------- passport / ID machine-readable zone ----------

_MRZ_RE = re.compile(r"^[A-Z0-9<]{30,44}$", re.M)


def find_mrz(text: str) -> list[Finding]:
    lines = [l.replace(" ", "") for l in text.upper().splitlines()]
    mrz = [l for l in lines if _MRZ_RE.match(l) and l.count("<") >= 3]
    if len(mrz) >= 2 or any(l.startswith(("P<", "I<", "ID")) and "<<" in l for l in mrz):
        return [Finding("id_document", HIGH, "MRZ lines detected",
                        "passport or ID card photo")]
    return []


# ---------- passwords, recovery codes, keys ----------

_PWD_RE = re.compile(r"\b(?:password|passwd|pwd|passcode|пароль)\s*[:=]\s*(\S{4,})", re.I)
_RECOVERY_RE = re.compile(r"\b(backup codes?|recovery codes?|recovery key|резервн\w* код\w*)\b", re.I)
_CODE_LINE_RE = re.compile(r"\b(?:\d{4}[ -]?\d{4}|[a-z0-9]{4,5}-[a-z0-9]{4,5})\b", re.I)

_KEY_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("api_key_openai", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("api_key_anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}")),
]


def find_passwords(text: str) -> list[Finding]:
    return [Finding("password", MEDIUM, "password: " + _mask(m.group(1), 1, 1),
                    "password written next to a label")
            for m in _PWD_RE.finditer(text)]


def find_recovery_codes(text: str) -> list[Finding]:
    codes = _CODE_LINE_RE.findall(text)
    if _RECOVERY_RE.search(text) and len(codes) >= 4:
        return [Finding("recovery_codes", HIGH, f"{len(codes)} codes",
                        "2FA backup / recovery codes")]
    return []


def find_keys(text: str) -> list[Finding]:
    out = []
    for kind, rx in _KEY_PATTERNS:
        for m in rx.finditer(text):
            out.append(Finding(kind, HIGH, _mask(m.group(), 6, 2), "secret key or token"))
    return out


# ---------- crypto addresses (low: public, but links you to a wallet) ----------

_ADDR_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|0x[a-fA-F0-9]{40})\b")


def find_addresses(text: str) -> list[Finding]:
    return [Finding("crypto_address", LOW, _mask(m.group(), 6, 4), "wallet address")
            for m in _ADDR_RE.finditer(text)]


ALL = [find_seed_phrases, find_cards, find_ibans, find_mrz,
       find_recovery_codes, find_keys, find_passwords, find_addresses]


def scan_text(text: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in ALL:
        out.extend(fn(text))
    # sk-ant keys also match the generic sk- rule, keep one
    kinds = {f.kind for f in out}
    if "api_key_anthropic" in kinds:
        out = [f for f in out if f.kind != "api_key_openai"]
    return out
