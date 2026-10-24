"""Edge feature encoding for GTAE-IDS (paper Fig. 3 / Sec. III-A.2).

A TCP/IPv4 packet is reduced to 25 bytes:

* 9 bytes from the fixed IP header: total length, identification,
  flags/fragment offset, TTL, header checksum (offsets 2-8, 10, 11);
* 16 bytes from the fixed TCP header: sequence, acknowledgment,
  data offset/flags, window, checksum, urgent pointer (offsets 4-19).

Ethernet, IP/TCP options, payload, addresses, ports and protocol are dropped.
Bytes are then scaled to [0, 1] and placed in a 50-d slot per packet so that
the direction (forward/backward) is encoded by which half is non-zero.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray

KEPT_BYTES = 25
BLOCK_DIM = 2 * KEPT_BYTES

IP_KEEP = (2, 3, 4, 5, 6, 7, 8, 10, 11)
TCP_KEEP = (4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)

# Forward = sender of the first observed packet (0), backward = the peer (1).
DIR_FWD = 0
DIR_BWD = 1


def strip_headers(ip_tcp: bytes) -> bytes:
    """Return the 25 bytes kept from a raw IPv4+TCP header (no payload)."""
    if len(ip_tcp) < 20:
        raise ValueError(f"packet too short for an IPv4 header: {len(ip_tcp)} bytes")
    ihl = (ip_tcp[0] & 0x0F) * 4
    if ihl < 20 or len(ip_tcp) < ihl + 20:
        raise ValueError(
            f"truncated or malformed IP/TCP header: ihl={ihl}, len={len(ip_tcp)}"
        )
    tcp = ip_tcp[ihl : ihl + 20]
    out = bytes(ip_tcp[i] for i in IP_KEEP) + bytes(tcp[i] for i in TCP_KEEP)
    assert len(out) == KEPT_BYTES
    return out


def normalize(kept: bytes) -> NDArray[np.float32]:
    """Map the 25 raw bytes to float32 in [0, 1]."""
    if len(kept) != KEPT_BYTES:
        raise ValueError(f"expected {KEPT_BYTES} bytes, got {len(kept)}")
    return np.frombuffer(kept, dtype=np.uint8).astype(np.float32) / 255.0


def pack_direction(x25: NDArray[np.float32], direction: int) -> NDArray[np.float32]:
    """Place a 25-d packet vector in the forward or backward half of a 50-d slot."""
    if direction not in (DIR_FWD, DIR_BWD):
        raise ValueError(f"direction must be {DIR_FWD} or {DIR_BWD}, got {direction}")
    slot = np.zeros(BLOCK_DIM, dtype=np.float32)
    if direction == DIR_FWD:
        slot[:KEPT_BYTES] = x25
    else:
        slot[KEPT_BYTES:] = x25
    return slot


def encode_edge(
    packets: Sequence[tuple[bytes, int]], p: int
) -> NDArray[np.float32]:
    """Encode the first ``p`` packets of a flow as a (50 * p,) edge feature.

    ``packets`` holds ``(kept25_bytes, direction)`` in arrival order.
    """
    if p < 1:
        raise ValueError(f"p must be >= 1, got {p}")
    if len(packets) < p:
        raise ValueError(f"flow has {len(packets)} packets, need at least {p}")
    blocks = [pack_direction(normalize(kept), direction) for kept, direction in packets[:p]]
    return np.concatenate(blocks)
