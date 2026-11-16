"""A5 header-hygiene mask: exactly TTL + both checksums are zeroed per packet."""

from __future__ import annotations

import numpy as np
import pytest

from src.packet_encoder import (
    BLOCK_DIM,
    HYGIENE_POSITIONS,
    KEPT_BYTES,
    apply_hygiene,
    encode_edge,
    hygiene_mask,
)

# Byte positions in the 25-byte packet vector, derived from the header offsets
# documented in src/packet_encoder.py: IP_KEEP = (2..8, 10, 11), TCP_KEEP = (4..19).
TTL_POSITION = 6           # IP offset 8
IP_CHECKSUM_POSITIONS = (7, 8)      # IP offsets 10, 11
TCP_CHECKSUM_POSITIONS = (21, 22)   # TCP offsets 16, 17


def test_hygiene_positions_are_ttl_and_checksums() -> None:
    assert set(HYGIENE_POSITIONS) == {TTL_POSITION, *IP_CHECKSUM_POSITIONS, *TCP_CHECKSUM_POSITIONS}


def test_hygiene_mask_covers_both_directions_of_every_packet() -> None:
    p = 3
    mask = hygiene_mask(p)
    assert mask.shape == (BLOCK_DIM * p,)
    assert mask.sum() == len(HYGIENE_POSITIONS) * p * 2
    for block in range(p):
        for direction_offset in (0, KEPT_BYTES):
            base = block * BLOCK_DIM + direction_offset
            for position in HYGIENE_POSITIONS:
                assert mask[base + position]


def test_apply_hygiene_zeroes_only_the_hygiene_bytes() -> None:
    p = 2
    x = np.ones((4, BLOCK_DIM * p), dtype=np.float32)
    out = apply_hygiene(x, p)
    assert out.shape == x.shape
    assert out.dtype == np.float32
    # input untouched
    np.testing.assert_allclose(x, 1.0)
    zero = out == 0.0
    assert zero.sum(axis=1).tolist() == [len(HYGIENE_POSITIONS) * 2 * p] * 4
    np.testing.assert_array_equal(zero[0], hygiene_mask(p))
    np.testing.assert_allclose(out[~zero], 1.0)


def test_apply_hygiene_matches_encoding_zeroed_bytes() -> None:
    p = 2
    raw = bytes(range(25))
    zeroed = bytes(0 if i in HYGIENE_POSITIONS else b for i, b in enumerate(raw))
    packets_raw = [(raw, 0), (raw, 1)]
    packets_zeroed = [(zeroed, 0), (zeroed, 1)]
    got = apply_hygiene(encode_edge(packets_raw, p).reshape(1, -1), p)
    want = encode_edge(packets_zeroed, p).reshape(1, -1)
    np.testing.assert_allclose(got, want)


def test_apply_hygiene_rejects_wrong_width() -> None:
    with pytest.raises(ValueError):
        apply_hygiene(np.zeros((2, 50), dtype=np.float32), p=2)
    with pytest.raises(ValueError):
        hygiene_mask(0)
