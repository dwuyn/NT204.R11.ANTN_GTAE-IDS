"""Tests for the B2 baseline: mean-aggregation autoencoder (E-GraphSAGE-style)."""

from __future__ import annotations

import numpy as np
import pytest
import torch

from src.embed import load_model
from src.line_graph import build_line_graph
from src.model_egsage import EGraphSAGE, MeanAggLayer
from src.model_gtae import ARCH, GTAE


def _line(num_edges: int, num_nodes: int) -> torch.Tensor:
    edge_index = np.stack(
        [np.arange(num_edges) % num_nodes, (np.arange(num_edges) + 1) % num_nodes]
    )
    line = build_line_graph(edge_index, num_nodes, max_neighbors=32, seed=0)
    return torch.as_tensor(line, dtype=torch.long)


@pytest.mark.parametrize("p", [2, 8])
def test_egsage_forward_shapes(p):
    num_edges, num_nodes = 40, 12
    model = EGraphSAGE(p)
    x = torch.rand(num_edges, 50 * p)
    recon, z = model(x, _line(num_edges, num_nodes))
    assert recon.shape == x.shape
    assert z.shape == (num_edges, ARCH[p]["d"])


def test_egsage_keeps_transformer_depth():
    for p in (2, 4, 8):
        assert len(EGraphSAGE(p).layers) == len(GTAE(p).layers) == ARCH[p]["layers"]
        assert all(isinstance(layer, MeanAggLayer) for layer in EGraphSAGE(p).layers)


def test_mean_agg_layer_shape_and_degree_normalisation():
    layer = MeanAggLayer(8)
    x = torch.rand(5, 8)
    # one self-loop per node: mean aggregation must equal the node's own message
    loops = torch.stack([torch.arange(5), torch.arange(5)])
    out = layer(x, loops)
    assert out.shape == x.shape
    empty = layer(x, torch.zeros((2, 0), dtype=torch.long))
    assert torch.isfinite(empty).all()


def test_egsage_gradients_reach_input_projection():
    model = EGraphSAGE(2)
    x = torch.rand(30, 100)
    recon, _ = model(x, _line(30, 9))
    torch.nn.functional.mse_loss(recon, x).backward()
    grad = model.input_proj.weight.grad
    assert grad is not None and torch.count_nonzero(grad) > 0


def test_load_model_roundtrip_recognises_egsage(tmp_path):
    model = EGraphSAGE(2)
    checkpoint = {
        "state_dict": model.state_dict(),
        "p": 2,
        "arch": ARCH[2],
        "arch_name": "egsage",
        "pe_dim": 8,
        "use_pe": True,
    }
    path = tmp_path / "model.pt"
    torch.save(checkpoint, path)
    loaded, ckpt = load_model(path, torch.device("cpu"))
    assert isinstance(loaded, EGraphSAGE)
    assert ckpt["arch_name"] == "egsage"


def test_load_model_defaults_to_transformer(tmp_path):
    model = GTAE(2)
    path = tmp_path / "model.pt"
    torch.save(
        {"state_dict": model.state_dict(), "p": 2, "arch": ARCH[2], "pe_dim": 8, "use_pe": True},
        path,
    )
    loaded, _ = load_model(path, torch.device("cpu"))
    assert type(loaded) is GTAE
