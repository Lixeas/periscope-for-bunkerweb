"""Hand-encoded vectors following the Biscuit v3 schema (schema.proto):
Biscuit{rootKeyId=1, authority=2: SignedBlock{block=1: Block{symbols=1 (repeated string), ...}}}.
The authority block of a real BunkerWeb token also contains facts/figures; they are simulated here
by a varint field (version=5) and an opaque field 6, which must be ignored. No real token could be
generated (biscuit-python unavailable for Python 3.14)."""
import base64

import pytest

from periscope.biscuit_version import version_from_token


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def ld(num: int, data: bytes) -> bytes:
    return varint(num << 3 | 2) + varint(len(data)) + data


def token_bytes(symbols: list[str]) -> bytes:
    block = varint(5 << 3) + varint(3)  # version = 3
    block += b"".join(ld(1, s.encode()) for s in symbols) + ld(6, b"\x08\x01")
    signed = ld(1, block) + ld(2, b"\x00" * 64)  # block + signature
    return ld(1, b"") + ld(2, signed) + varint(9 << 3 | 1) + b"\x00" * 8


def b64(raw: bytes, urlsafe=True, pad=True) -> str:
    s = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return s if pad else s.rstrip("=")


SYMS = ["periscope", "10.0.0.2", "10.0.0.2:8888", "1.6.17", "api_user"]


def test_version_found_among_symbols():
    assert version_from_token(b64(token_bytes(SYMS))) == "1.6.17"


def test_prerelease_and_first_match():
    assert version_from_token(b64(token_bytes(["u", "1.7.0-rc1", "1.6.17"]))) == "1.7.0-rc1"


def test_missing_version_none_ipv4_not_returned():
    assert version_from_token(b64(token_bytes(["periscope", "10.0.0.2", "api_user"]))) is None


@pytest.mark.parametrize("pad", [True, False])
@pytest.mark.parametrize("urlsafe", [True, False])
def test_base64_variants(pad, urlsafe):
    # bytes 0xfb/0xff in the signature => '+' '/' in the standard alphabet
    raw = token_bytes(["x", "1.6.17"]).replace(b"\x00" * 8, b"\xfb\xff\xfe" * 3)
    assert version_from_token(b64(raw, urlsafe, pad)) == "1.6.17"


def test_truncated_protobuf_none():
    raw = token_bytes(SYMS)
    for cut in range(0, len(raw) - 1, 7):
        version_from_token(b64(raw[:cut]))  # never raises
    assert version_from_token(b64(raw[:30])) is None


def test_malformed_wire_none():
    assert version_from_token(b64(b"\x12\xff\xff\xff\xff\x0f")) is None  # huge length
    assert version_from_token(b64(b"\x13\x00")) is None  # type de fil 3
    assert version_from_token(b64(b"\x80" * 20)) is None  # varint interminable


@pytest.mark.parametrize("tok", ["", "not base64 !!!", "static-api-token-0123456789abcdef", "é", "A", "====="])
def test_garbage_none(tok):
    assert version_from_token(tok) is None


def test_non_string_none():
    assert version_from_token(None) is None  # type: ignore[arg-type]


def test_oversized_none():
    assert version_from_token(b64(token_bytes(SYMS + ["z" * 70000]))) is None
    assert version_from_token("A" * 1_000_000) is None


def test_version_truncated_to_32():
    assert len(version_from_token(b64(token_bytes(["1.2.3-" + "a" * 60]))) or "") == 32

