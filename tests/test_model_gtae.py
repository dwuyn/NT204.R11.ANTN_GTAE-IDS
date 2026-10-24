"""Shape/backward tests for the GTAE model (CPU, tiny graphs)."""

from __future__ import annotations

import numpy as np
import pytest
import torch

from src.line_graph import build_line_graph
from src.model_gtae import ARCH, GTAE


def _chain(n_edges: int):
    edge_index = np.stack(
        [np.arange(n_edges), np.arange(1, n_edges + 1)], axis=0
    ).astype(np.int64)
    line = build_line_graph(edge_index, num_nodes=n_edges + 1)
    return torch.as_tensor(line, dtype=torch.long)


@pytest.mark.parametrize("p", sorted(ARCH))
def test_forward_backward_shapes(p):
    torch.manual_seed(0)
    n_edges = 20
    line = _chain(n_edges)
    x = torch.rand(n_edges, 50 * p)
    pe = torch.rand(n_edges, 8)

    model = GTAE(p)
    out, z = model(x, line, pe)

    assert out.shape == (n_edges, 50 * p)
    assert z.shape == (n_edges, ARCH[p]["d"])
    assert len(model.layers) == ARCH[p]["layers"]
    assert torch.isfinite(out).all() and torch.isfinite(z).all()

    loss = out.pow(2).mean()
    loss.backward()
    grads = [param.grad for param in model.parameters() if param.requires_grad]
    assert grads and all(grad is not None and torch.isfinite(grad).all() for grad in grads)


def test_pe_is_optional():
    model = GTAE(4)
    line = _chain(10)
    out, _ = model(torch.rand(10, 200), line)
    assert out.shape == (10, 200)


def test_invalid_p_raises():
    with pytest.raises(ValueError):
        GTAE(9)
