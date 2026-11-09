"""Laplacian positional encoding for edge-level GTAE (paper eq. 3, k=8).

The paper does not publish k; k=8 is a recorded assumption. Node encodings are
the k smallest non-trivial Laplacian eigenvectors; an edge encoding is
``phi_u + phi_v`` (symmetric, documented assumption). Signs are arbitrary, so
training randomly flips each eigenvector's sign per batch (Dwivedi & Bresson).
"""

from __future__ import annotations

import numpy as np
from scipy.sparse import coo_matrix, diags
from scipy.sparse.linalg import eigsh

PE_DIM = 8


def laplacian_pe(
    edge_index: np.ndarray, num_nodes: int, k: int = PE_DIM, seed: int = 0
) -> np.ndarray:
    """Return ``[num_nodes, k]`` normalized-Laplacian eigenvectors.

    ARPACK otherwise uses an unseeded random start vector; passing ``v0``
    makes embeddings reproducible across runs.
    """
    if num_nodes <= 1 or edge_index.shape[1] == 0 or k < 1:
        return np.zeros((num_nodes, k), dtype=np.float32)

    row = np.concatenate([edge_index[0], edge_index[1]])
    col = np.concatenate([edge_index[1], edge_index[0]])
    data = np.ones(row.size, dtype=np.float32)
    adjacency = coo_matrix((data, (row, col)), shape=(num_nodes, num_nodes)).tocsr()
    adjacency.data = np.ones_like(adjacency.data)  # collapse parallel edges

    degree = np.asarray(adjacency.sum(axis=1)).ravel()
    inv_sqrt = 1.0 / np.sqrt(np.maximum(degree, 1.0))
    laplacian = diags(np.ones(num_nodes)) - diags(inv_sqrt) @ adjacency @ diags(inv_sqrt)

    n_eigs = min(k + 1, num_nodes - 1)
    if n_eigs < 1:
        return np.zeros((num_nodes, k), dtype=np.float32)
    v0 = np.random.default_rng(seed).standard_normal(num_nodes)
    try:
        values, vectors = eigsh(
            laplacian, k=n_eigs, sigma=1e-6, which="LM", v0=v0
        )
        vectors = vectors[:, np.argsort(values)]
    except Exception:
        try:
            values, vectors = eigsh(laplacian, k=n_eigs, which="SA", v0=v0)
            vectors = vectors[:, np.argsort(values)]
        except Exception:
            # Small/ill-conditioned graphs: dense fallback.
            values, vectors = np.linalg.eigh(laplacian.toarray())
            vectors = vectors[:, np.argsort(values)]
    # Sort columns by eigenvalue (eigsh does not guarantee order) and drop the
    # trivial constant eigenvector.
    if vectors.shape[1] > 1:
        vectors = vectors[:, 1 : k + 1]
    pe = np.zeros((num_nodes, k), dtype=np.float32)
    pe[:, : vectors.shape[1]] = vectors[:, :k]
    return pe


def edge_pe(node_pe: np.ndarray, edge_index: np.ndarray) -> np.ndarray:
    """Edge encoding ``phi_u + phi_v`` for each edge."""
    return node_pe[edge_index[0]] + node_pe[edge_index[1]]
