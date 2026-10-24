"""Line-graph construction for edge-level attention (design doc §4.6).

Each original edge becomes a node; two nodes are adjacent when the original
edges share an endpoint. Hub cliques are capped at ``max_neighbors`` to avoid
quadratic blow-ups (paper assumption K_max = 32), then the result is
symmetrised and self-loops are added.
"""

from __future__ import annotations

import random
from typing import Iterable

import numpy as np


def build_line_graph(
    edge_index: np.ndarray,
    num_nodes: int | None = None,
    max_neighbors: int | None = 32,
    seed: int = 0,
    add_self_loops: bool = True,
) -> np.ndarray:
    """Return a directed ``[2, L]`` line-graph edge index (symmetrised)."""
    edge_index = np.asarray(edge_index)
    n_edges = edge_index.shape[1] if edge_index.ndim == 2 else 0
    if n_edges == 0:
        return np.zeros((2, 0), dtype=np.int64)
    if num_nodes is None:
        num_nodes = int(edge_index.max()) + 1

    incident: list[list[int]] = [[] for _ in range(num_nodes)]
    for edge_id, (u, v) in enumerate(edge_index.T):
        incident[int(u)].append(edge_id)
        incident[int(v)].append(edge_id)

    rng = random.Random(seed)
    src: list[int] = []
    dst: list[int] = []
    for node in range(num_nodes):
        ids = incident[node]
        if not ids:
            continue
        if max_neighbors is not None and len(ids) > max_neighbors:
            ids = rng.sample(ids, max_neighbors)
        for a in ids:
            for b in ids:
                if a != b:
                    src.append(a)
                    dst.append(b)

    # Symmetrise: attention messages must flow both ways on an undirected graph.
    src_arr = np.asarray(src + dst, dtype=np.int64)
    dst_arr = np.asarray(dst + src, dtype=np.int64)
    if add_self_loops:
        loops = np.arange(n_edges, dtype=np.int64)
        src_arr = np.concatenate([src_arr, loops])
        dst_arr = np.concatenate([dst_arr, loops])
    return np.stack([src_arr, dst_arr])
