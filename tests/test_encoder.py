"""Unit tests for src.packet_encoder (paper Fig. 3 test vector + leakage checks)."""

from __future__ import annotations

import socket
import struct

import numpy as np
import pytest

from src.packet_encoder import (
    BLOCK_DIM,
    DIR_BWD,
    DIR_FWD,
    KEPT_BYTES,
    encode_edge,
    normalize,
    pack_direction,
    strip_headers,
)

# Fig. 3 of the paper: raw IPv4 header + fixed 20-byte TCP header.
FIG3_IP = bytes.fromhex("450001c7c50040004006deaac0a80a32c0a80a03")
FIG3_TCP = bytes.fromhex("db2c0cc46a70fd5c3630dfa980180179d0aa0000")
FIG3_KEPT = bytes.fromhex("01c7c500400040deaa6a70fd5c3630dfa980180179d0aa0000")


def test_fig3_vector():
    assert strip_headers(FIG3_IP + FIG3_TCP) == FIG3_KEPT
    assert len(FIG3_KEPT) == KEPT_BYTES


def test_ip_options_dropped():
    # IHL = 6 (24-byte IP header) with 4 option bytes; kept bytes must not change.
    with_options = b"\x46" + FIG3_IP[1:20] + bytes.fromhex("01010100") + FIG3_TCP
    assert strip_headers(with_options) == FIG3_KEPT


def test_tcp_options_dropped():
    # Data offset is already 8 in the test vector; append the 12 option bytes.
    with_options = FIG3_IP + FIG3_TCP + bytes.fromhex("010101010101010101010101")
    assert strip_headers(with_options) == FIG3_KEPT


def test_normalize_range():
    raw = bytes([0] + [1] * (KEPT_BYTES - 2) + [255])
    out = normalize(raw)
    assert out.dtype == np.float32
    assert out[0] == 0.0 and out[-1] == 1.0
    np.testing.assert_allclose(out[1], 1 / 255)


def test_direction_packing():
    x = normalize(FIG3_KEPT)
    fwd = pack_direction(x, DIR_FWD)
    bwd = pack_direction(x, DIR_BWD)
    assert fwd.shape == (BLOCK_DIM,)
    np.testing.assert_array_equal(fwd[:KEPT_BYTES], x)
    assert np.all(fwd[KEPT_BYTES:] == 0)
    np.testing.assert_array_equal(bwd[KEPT_BYTES:], x)
    assert np.all(bwd[:KEPT_BYTES] == 0)


def test_encode_edge_layout_and_dims():
    x = normalize(FIG3_KEPT)
    with pytest.raises(ValueError):
        encode_edge([(FIG3_KEPT, DIR_FWD)], p=3)

    packets = [(FIG3_KEPT, DIR_FWD), (FIG3_KEPT, DIR_BWD), (FIG3_KEPT, DIR_FWD)]
    out = encode_edge(packets, p=3)
    assert out.shape == (3 * BLOCK_DIM,) == (150,)
    # packet 1 (fwd): x | 0
    np.testing.assert_array_equal(out[:KEPT_BYTES], x)
    assert np.all(out[KEPT_BYTES:BLOCK_DIM] == 0)
    # packet 2 (bwd): 0 | x
    assert np.all(out[BLOCK_DIM : BLOCK_DIM + KEPT_BYTES] == 0)
    np.testing.assert_array_equal(out[BLOCK_DIM + KEPT_BYTES : 2 * BLOCK_DIM], x)
    # packet 3 (fwd): x | 0
    np.testing.assert_array_equal(out[2 * BLOCK_DIM : 2 * BLOCK_DIM + KEPT_BYTES], x)
    assert np.all(out[2 * BLOCK_DIM + KEPT_BYTES :] == 0)


def test_no_direct_ip_port_leak():
    # Mutating addresses/ports without touching checksums must not change the vector.
    ip = bytearray(FIG3_IP)
    ip[12:16] = socket.inet_aton("203.0.113.7")
    ip[16:20] = socket.inet_aton("198.51.100.9")
    tcp = bytearray(FIG3_TCP)
    struct.pack_into("!HH", tcp, 0, 45000, 443)
    assert strip_headers(bytes(ip) + bytes(tcp)) == FIG3_KEPT


def _ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_packet(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp = bytearray(20)
    struct.pack_into("!HHIIBBHHH", tcp, 0, sport, dport, 1000, 2000, 0x50, 0x18, 502, 0, 0)
    ip = bytearray(20)
    struct.pack_into(
        "!BBHHHBBH4s4s",
        ip,
        0,
        0x45,
        0,
        40,  # total length
        0x1234,
        0x4000,
        64,
        6,  # TCP
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    struct.pack_into("!H", ip, 10, _ones_complement(bytes(ip)))
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, 20)
    struct.pack_into("!H", tcp, 16, _ones_complement(pseudo + bytes(tcp)))
    return bytes(ip) + bytes(tcp)


def test_checksum_dependency_documented_leak():
    """Indirect leak: IP/TCP checksums are functions of dropped IP/port fields."""
    a = strip_headers(_build_packet("10.0.0.1", "10.0.0.2", 1234, 80))
    b = strip_headers(_build_packet("10.0.0.1", "10.0.0.9", 1234, 80))
    changed = {i for i, (x, y) in enumerate(zip(a, b)) if x != y}
    # IP checksum lives at kept indices 7-8, TCP checksum at 21-22. Nothing else
    # may change when only the destination address changes.
    assert changed <= {7, 8, 21, 22}
    assert changed & {7, 8}, "IP header checksum should react to the destination IP"
    assert changed & {21, 22}, "TCP checksum covers the IP pseudo-header"


def test_rejects_truncated_or_malformed():
    with pytest.raises(ValueError):
        strip_headers(FIG3_IP[:19])
    with pytest.raises(ValueError):
        strip_headers(FIG3_IP)  # no TCP header
    with pytest.raises(ValueError):
        strip_headers(b"\x40" + FIG3_IP[1:20] + FIG3_TCP)  # IHL = 0
