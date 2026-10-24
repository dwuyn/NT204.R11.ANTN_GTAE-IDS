"""Tests for line-graph construction."""

from __future__ import annotations

import numpy as np

from src.line_graph import build_line_graph


def test_chain_line_graph_is_symmetric_with_self_loops():
    # 5 edges in a chain: edge i shares a node with edge i+1.
    edge_index = np.array([[0, 1, 2, 3, 4], [1, 2, 3, 4, 5]], dtype=np.int64)
    line = build_line_graph(edge_index, num_nodes=6, max_neighbors=None)
    pairs = set(zip(line[0].tolist(), line[1].tolist()))

    for i in range(5):
        assert (i, i) in pairs
    for i in range(4):
        assert (i, i + 1) in pairs and (i + 1, i) in pairs
    assert (0, 2) not in pairs


def test_max_neighbors_caps_hub_clique():
    # Star: 10 edges all share node 0, so the full line graph is a 10-clique.
    src = np.zeros(10, dtype=np.int64)
    dst = np.arange(1, 11, dtype=np.int64)
    edge_index = np.stack([src, dst])

    full = build_line_graph(edge_index, num_nodes=11, max_neighbors=None)
    capped = build_line_graph(edge_index, num_nodes=11, max_neighbors=3, seed=0)

    assert full.shape[1] == 10 * 9 * 2 + 10  # directed clique + one self-loop each
    assert capped.shape[1] < full.shape[1]
    assert capped.shape[1] == 3 * 2 * 2 + 10  # 3-clique from sampled neighbours + loops


def test_empty_graph():
    edge_index = np.zeros((2, 0), dtype=np.int64)
    assert build_line_graph(edge_index).shape == (2, 0)
