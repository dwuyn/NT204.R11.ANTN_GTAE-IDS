"""B2 baseline: E-GraphSAGE-style mean-aggregation autoencoder (should model).

The paper's ablation asks whether the *attention* operator matters, or whether
any neighborhood aggregation would do. This module keeps everything about GTAE
fixed (input projection, PE projection, bottleneck width, decoder, depth) and
replaces only `EdgeTransformerLayer` with mean aggregation over the same line
graph — so a difference in TPR/AUROC is attributable to the operator, not to
capacity or depth.
"""

from __future__ import annotations

import torch
from torch import nn

from src.model_gtae import ARCH, PE_DIM, GTAE


class MeanAggLayer(nn.Module):
    """Mean aggregation over line-graph in-neighbours + residual FFN.

    Same residual/normalisation layout as `EdgeTransformerLayer`: the only
    change is *what* is aggregated (mean of projected messages instead of
    multi-head attention weights).
    """

    def __init__(self, d: int, dropout: float = 0.05):
        super().__init__()
        self.msg = nn.Linear(d, d)
        self.norm = nn.LayerNorm(d)
        self.norm2 = nn.LayerNorm(d)
        self.ffn = nn.Sequential(nn.Linear(d, 2 * d), nn.ReLU(), nn.Linear(2 * d, d))
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, line_edge_index: torch.Tensor) -> torch.Tensor:
        n = x.size(0)
        src, dst = line_edge_index[0], line_edge_index[1]
        msg = self.msg(x)
        aggregated = torch.zeros_like(x).index_add_(0, dst, msg[src])
        degree = torch.zeros(n, dtype=x.dtype, device=x.device).index_add_(
            0, dst, torch.ones_like(dst, dtype=x.dtype)
        )
        h = self.norm(x + self.drop(aggregated / degree.clamp(min=1).unsqueeze(-1)))
        return self.norm2(h + self.ffn(h))


class EGraphSAGE(GTAE):
    """GTAE with mean aggregation instead of edge attention (same depth/width)."""

    def __init__(self, p: int, pe_dim: int = PE_DIM, dropout: float = 0.05):
        super().__init__(p, pe_dim=pe_dim, dropout=dropout)
        cfg = ARCH[p]
        self.layers = nn.ModuleList(
            [MeanAggLayer(cfg["d"], dropout) for _ in range(cfg["layers"])]
        )
