"""Rolling-window graph for online (per-flow, pcap-replay) inference.

The offline pipeline builds one static graph per split. A streaming deployment
cannot: flows arrive and expire, so the graph the encoder sees at time ``t`` is
the set of flows whose last packet is within ``window`` seconds of ``t``. This
module holds that graph and nothing else — graph/PE code lives in
``src.line_graph``/``src.pe``, edge encoding in ``src.cic_graph``.

Rules (fixed by the measurement protocol, docs/DECISIONS.md §4):

* edge attribute = ``encode_edge_padded(packets[:p], p)``: the same 50*p vector
  the offline graphs use, zero-padded when a flow has fewer than ``p`` packets;
* endpoints are ``(ip, port)`` pairs mapped to a monotone dict of ids that is
  never pruned, so ``num_nodes`` counts every endpoint seen so far;
* ``expire`` is called with the current flow's ``t_last`` before ``arrays``; the
  current flow is then the last of the ``E`` rows.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

import numpy as np
import torch

from src.cic_graph import encode_edge_padded
from src.line_graph import build_line_graph
from src.pe import PE_DIM, edge_pe, laplacian_pe

INITIAL_CAPACITY = 1024


@dataclass
class WindowGraph:
    """Flows active in the last ``window`` seconds, as a graph + edge features."""

    window: float = 120.0
    _node_ids: dict[tuple[str, int], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._capacity = INITIAL_CAPACITY
        self._u = np.zeros(self._capacity, dtype=np.int32)
        self._v = np.zeros(self._capacity, dtype=np.int32)
        self._tlast = np.zeros(self._capacity, dtype=np.float64)
        self._alive = np.zeros(self._capacity, dtype=bool)
        self._expiry: list[tuple[float, int]] = []
        self._size = 0
        self._p: int | None = None
        self._attr: np.ndarray | None = None

    # -- endpoints ---------------------------------------------------------
    def _node_id(self, endpoint: tuple[str, int]) -> int:
        node = self._node_ids.get(endpoint)
        if node is None:
            node = len(self._node_ids)
            self._node_ids[endpoint] = node
        return node

    @property
    def num_nodes(self) -> int:
        """Distinct endpoints observed so far; never shrinks."""
        return len(self._node_ids)

    @property
    def num_edges(self) -> int:
        """Edges currently inside the window."""
        return int(self._alive[: self._size].sum())

    # -- mutation ----------------------------------------------------------
    def _grow(self) -> None:
        self._capacity *= 2
        for name, dtype in (
            ("_u", np.int32),
            ("_v", np.int32),
            ("_tlast", np.float64),
            ("_alive", bool),
        ):
            grown = np.zeros(self._capacity, dtype=dtype)
            grown[: self._size] = getattr(self, name)[: self._size]
            setattr(self, name, grown)
        if self._attr is not None:
            widened = np.zeros((self._capacity, 50 * self._p), dtype=np.float32)
            widened[: self._size] = self._attr[: self._size]
            self._attr = widened

    def add(self, flow: Mapping[str, Any], p: int) -> int:
        """Add ``flow``; return the row index of its edge in ``arrays(p)``."""
        if self._p is None:
            self._p = p
            self._attr = np.zeros((self._capacity, 50 * p), dtype=np.float32)
        elif p != self._p:
            raise ValueError(f"window graph was built for p={self._p}, got p={p}")
        if self._size == self._capacity:
            self._grow()
        row = self._size
        self._u[row] = self._node_id((str(flow["src_ip"]), int(flow["src_port"])))
        self._v[row] = self._node_id((str(flow["dst_ip"]), int(flow["dst_port"])))
        self._tlast[row] = float(flow["t_last"])
        packets = [(kept, direction) for _, kept, direction in flow["packets"][:p]]
        self._attr[row] = encode_edge_padded(packets, p)
        self._alive[row] = True
        self._size += 1
        heapq.heappush(self._expiry, (float(flow["t_last"]), row))
        if self._size > 2 * self.num_edges + INITIAL_CAPACITY:
            self._compact()
        return self.num_edges - 1

    def _compact(self) -> None:
        """Drop dead rows and renumber, so a long replay keeps bounded memory."""
        alive = np.flatnonzero(self._alive[: self._size])
        kept = alive.size
        self._u[:kept] = self._u[alive]
        self._v[:kept] = self._v[alive]
        self._tlast[:kept] = self._tlast[alive]
        self._attr[:kept] = self._attr[alive]
        self._alive[:kept] = True
        self._alive[kept : self._size] = False
        self._size = int(kept)
        self._expiry = [(self._tlast[i], i) for i in range(kept)]
        heapq.heapify(self._expiry)

    def expire(self, now: float) -> int:
        """Drop edges with ``t_last < now - window``; return how many were dropped."""
        horizon = now - self.window
        dropped = 0
        while self._expiry and self._expiry[0][0] < horizon:
            _, row = heapq.heappop(self._expiry)
            if self._alive[row]:
                self._alive[row] = False
                dropped += 1
        return dropped

    # -- read-out ----------------------------------------------------------
    def arrays(self, p: int) -> tuple[np.ndarray, np.ndarray]:
        """Edge index ``[2, E] int32`` and attributes ``[E, 50p] float32``."""
        if self._p is None:  # nothing added yet
            return np.zeros((2, 0), dtype=np.int32), np.zeros((0, 50 * p), dtype=np.float32)
        if p != self._p:
            raise ValueError(f"window graph was built for p={self._p}, got p={p}")
        alive = np.flatnonzero(self._alive[: self._size])
        edge_index = np.stack([self._u[alive], self._v[alive]]).astype(np.int32, copy=False)
        return edge_index, self._attr[alive]

    def __len__(self) -> int:
        return self.num_edges


def embed_rows(
    model: torch.nn.Module,
    edge_index: np.ndarray,
    edge_attr: np.ndarray,
    use_pe: bool,
    seed: int,
    timings: dict[str, float] | None = None,
) -> np.ndarray:
    """Encode every edge of a window graph; return ``[E, d]`` numpy embeddings.

    ``timings``, when given, is filled in-place with the seconds spent in
    ``line`` (line-graph build), ``pe`` (Laplacian + edge PE) and ``forward``.
    """
    clock = time.perf_counter
    mark = clock()
    num_nodes = int(edge_index.max()) + 1 if edge_index.size else 0
    line = build_line_graph(edge_index, num_nodes, max_neighbors=32, seed=seed)
    line_t = torch.as_tensor(line, dtype=torch.long)
    if timings is not None:
        timings["line"] = clock() - mark
        mark = clock()

    pe_t = None
    if use_pe:
        node_pe = laplacian_pe(edge_index, num_nodes, k=PE_DIM, seed=seed)
        pe_t = torch.from_numpy(edge_pe(node_pe, edge_index))
    if timings is not None:
        timings["pe"] = clock() - mark
        mark = clock()

    with torch.no_grad():
        z = model.encode(torch.from_numpy(edge_attr), line_t, pe_t)
    if timings is not None:
        timings["forward"] = clock() - mark
    return z.cpu().numpy()
