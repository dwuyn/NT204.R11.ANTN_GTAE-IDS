"""Tests for Laplacian positional encoding."""

from __future__ import annotations

import numpy as np

from src.pe import edge_pe, laplacian_pe


def test_path_graph_pe_shape_and_orthonormality():
    # Path 0-1-2-3-4-5.
    edge_index = np.stack([np.arange(5), np.arange(1, 6)])
    pe = laplacian_pe(edge_index, num_nodes=6, k=3)
    assert pe.shape == (6, 3)
    assert np.isfinite(pe).all()
    gram = pe.T @ pe
    np.testing.assert_allclose(gram, np.eye(3), atol=1e-4)


def test_small_graph_is_zero_padded():
    edge_index = np.array([[0], [1]])
    pe = laplacian_pe(edge_index, num_nodes=2, k=8)
    assert pe.shape == (2, 8)
    assert np.isfinite(pe).all()


def test_empty_and_single_node():
    assert laplacian_pe(np.zeros((2, 0), dtype=np.int64), 5, k=4).shape == (5, 4)
    assert laplacian_pe(np.zeros((2, 0), dtype=np.int64), 1, k=4).shape == (1, 4)


def test_edge_pe_is_symmetric_sum():
    edge_index = np.array([[0, 1, 2], [1, 2, 3]])
    node_pe = np.arange(16, dtype=np.float32).reshape(4, 4)
    out = edge_pe(node_pe, edge_index)
    assert out.shape == (3, 4)
    np.testing.assert_allclose(out[0], node_pe[0] + node_pe[1])


def test_laplacian_pe_is_deterministic():
    """ARPACK must use a seeded start vector, not its random default."""
    edge_index = np.stack([np.arange(39), np.arange(1, 40)])
    first = laplacian_pe(edge_index, num_nodes=40, k=8, seed=7)
    second = laplacian_pe(edge_index, num_nodes=40, k=8, seed=7)
    np.testing.assert_allclose(first, second, atol=1e-6)
