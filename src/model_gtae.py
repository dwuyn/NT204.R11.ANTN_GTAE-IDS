"""GTAE: edge-level graph transformer autoencoder (paper §III-B, Table III).

Implemented with plain PyTorch (no PyG dependency) so the same code runs on
CPU locally and on Kaggle. Attention runs on the line graph: an original edge
attends to edges sharing an endpoint (plus itself).
"""

from __future__ import annotations

import math
from typing import Iterable

import torch
from torch import nn

# Table III: encoder layers, heads, bottleneck d, decoder hidden widths.
ARCH: dict[int, dict] = {
    2: {"layers": 3, "heads": 3, "d": 8, "decoder": (32, 64)},
    3: {"layers": 3, "heads": 3, "d": 8, "decoder": (32, 64)},
    4: {"layers": 4, "heads": 4, "d": 16, "decoder": (32, 64, 128)},
    5: {"layers": 5, "heads": 6, "d": 32, "decoder": (32, 64, 128)},
    6: {"layers": 5, "heads": 6, "d": 32, "decoder": (32, 64, 128)},
    7: {"layers": 6, "heads": 8, "d": 64, "decoder": (32, 64, 128, 256)},
    8: {"layers": 6, "heads": 8, "d": 64, "decoder": (32, 64, 128, 256)},
}

PE_DIM = 8


def _grouped_softmax(scores: torch.Tensor, index: torch.Tensor, n_nodes: int) -> torch.Tensor:
    """Softmax over incoming line-graph edges for each destination node."""
    heads = scores.size(1)
    idx = index.unsqueeze(1).expand(-1, heads)
    max_per = torch.full(
        (n_nodes, heads), -1e30, dtype=scores.dtype, device=scores.device
    )
    max_per.scatter_reduce_(0, idx, scores, reduce="amax", include_self=True)
    exp = torch.exp(scores - max_per[index])
    denom = torch.zeros((n_nodes, heads), dtype=scores.dtype, device=scores.device)
    denom.index_add_(0, index, exp)
    return exp / (denom[index] + 1e-12)


class EdgeTransformerLayer(nn.Module):
    """Eq. (4)-(8): attention among edges sharing an endpoint + FFN."""

    def __init__(
        self,
        d: int,
        heads: int,
        ffn_mult: int = 2,
        dropout: float = 0.05,
        attn_dropout: float = 0.0,
    ):
        super().__init__()
        self.heads = heads
        self.d_k = d  # paper assumption: each head has dimension d
        self.q = nn.Linear(d, heads * d)
        self.k = nn.Linear(d, heads * d)
        self.v = nn.Linear(d, heads * d)
        self.out = nn.Linear(heads * d, d)
        self.norm1 = nn.LayerNorm(d)
        self.norm2 = nn.LayerNorm(d)
        self.ffn = nn.Sequential(
            nn.Linear(d, ffn_mult * d),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_mult * d, d),
        )
        self.attn_dropout = nn.Dropout(attn_dropout)
        self.ffn_dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, line_edge_index: torch.Tensor) -> torch.Tensor:
        n = x.size(0)
        src, dst = line_edge_index[0], line_edge_index[1]

        q = self.q(x).view(n, self.heads, self.d_k)
        k = self.k(x).view(n, self.heads, self.d_k)
        v = self.v(x).view(n, self.heads, self.d_k)

        scores = (q[dst] * k[src]).sum(-1) / math.sqrt(self.d_k)
        weights = _grouped_softmax(scores, dst, n)
        weights = self.attn_dropout(weights)

        messages = v[src] * weights.unsqueeze(-1)
        aggregated = torch.zeros(
            (n, self.heads, self.d_k), dtype=x.dtype, device=x.device
        ).index_add(0, dst, messages)
        aggregated = aggregated.reshape(n, self.heads * self.d_k)

        x = self.norm1(x + self.out(aggregated))
        x = self.norm2(x + self.ffn_dropout(self.ffn(x)))
        return x


class GTAE(nn.Module):
    """Symmetric autoencoder: edge transformer encoder + DNN decoder."""

    def __init__(self, p: int, pe_dim: int = PE_DIM, dropout: float = 0.05):
        super().__init__()
        if p not in ARCH:
            raise ValueError(f"p must be one of {sorted(ARCH)}, got {p}")
        cfg = ARCH[p]
        self.p = p
        self.in_dim = 50 * p
        d = cfg["d"]

        self.input_proj = nn.Linear(self.in_dim, d)
        self.pe_proj = nn.Linear(pe_dim, d)
        self.input_dropout = nn.Dropout(dropout)
        self.layers = nn.ModuleList(
            [
                EdgeTransformerLayer(
                    d,
                    cfg["heads"],
                    dropout=dropout,
                    attn_dropout=0.1 if layer == cfg["layers"] - 1 else 0.0,
                )
                for layer in range(cfg["layers"])
            ]
        )

        dims = [d, *cfg["decoder"], self.in_dim]
        decoder: list[nn.Module] = []
        for a, b in zip(dims[:-2], dims[1:-1]):
            decoder.extend([nn.Linear(a, b), nn.ReLU()])
        decoder.append(nn.Linear(dims[-2], dims[-1]))
        self.decoder = nn.Sequential(*decoder)

    def encode(
        self,
        edge_attr: torch.Tensor,
        line_edge_index: torch.Tensor,
        pe: torch.Tensor | None = None,
    ) -> torch.Tensor:
        x = self.input_proj(edge_attr)
        if pe is not None:
            x = x + self.pe_proj(pe)
        x = self.input_dropout(x)
        for layer in self.layers:
            x = layer(x, line_edge_index)
        return x

    def forward(
        self,
        edge_attr: torch.Tensor,
        line_edge_index: torch.Tensor,
        pe: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        z = self.encode(edge_attr, line_edge_index, pe)
        return self.decoder(z), z
