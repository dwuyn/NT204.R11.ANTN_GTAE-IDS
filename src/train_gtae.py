"""Train GTAE on benign edges (design doc §4.6, Table IV).

Each epoch samples ``batch_subgraphs`` connected edge-induced subgraphs of at
most ``max_edges`` edges from train1, reconstructs the 50p edge features with
MSE, and early-stops on a held-out 10% of train1 edges.

    python -m src.train_gtae --p 8 --graphs data/graphs/T --out experiments/gtae_p8
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import deque
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn

from src.graph_builder import GraphArrays, load_graph
from src.line_graph import build_line_graph
from src.model_gtae import ARCH, GTAE
from src.pe import PE_DIM, edge_pe, laplacian_pe


def _neighbor_lists(
    graph: GraphArrays,
    allowed: np.ndarray,
    k_max: int,
    seed: int,
) -> dict[int, list[int]]:
    line = build_line_graph(
        graph.edge_index, graph.num_nodes, max_neighbors=k_max, seed=seed
    )
    allowed_set = {int(x) for x in allowed}
    neighbors: dict[int, set[int]] = {}
    for a, b in zip(line[0].tolist(), line[1].tolist()):
        if a != b and b in allowed_set:
            neighbors.setdefault(a, set()).add(b)
    return {node: sorted(nbrs) for node, nbrs in neighbors.items()}


def _sample_subgraph(
    neighbors: dict[int, list[int]],
    allowed: np.ndarray,
    max_edges: int,
    rng: np.random.Generator,
) -> list[int]:
    seed = int(rng.choice(allowed))
    selected = {seed}
    queue = deque([seed])
    while queue and len(selected) < max_edges:
        current = queue.popleft()
        for neighbor in neighbors.get(current, ()):
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append(neighbor)
                if len(selected) >= max_edges:
                    break
    return sorted(selected)


def _make_batch(
    graph: GraphArrays,
    edge_ids: list[int],
    rng: np.random.Generator,
    use_pe: bool,
    sign_flip: bool,
    k_max: int,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor | None]:
    ids = np.asarray(edge_ids, dtype=np.int64)
    edge_index = graph.edge_index[:, ids]
    nodes, inverse = np.unique(edge_index, return_inverse=True)
    local_edge_index = inverse.reshape(2, -1).astype(np.int64)

    x = torch.from_numpy(graph.edge_attr[ids])
    line = build_line_graph(
        local_edge_index,
        len(nodes),
        max_neighbors=k_max,
        seed=int(rng.integers(0, 2**31 - 1)),
    )
    line_t = torch.as_tensor(line, dtype=torch.long)

    pe_t = None
    if use_pe:
        node_pe = laplacian_pe(local_edge_index, len(nodes), k=PE_DIM, seed=0)
        pe = edge_pe(node_pe, local_edge_index)
        if sign_flip:
            pe = pe * rng.choice([-1.0, 1.0], size=pe.shape[1]).astype(np.float32)
        pe_t = torch.from_numpy(pe)
    return x, line_t, pe_t


def _make_batched_batch(
    graph: GraphArrays,
    edge_id_groups: list[list[int]],
    rng: np.random.Generator,
    use_pe: bool,
    sign_flip: bool,
    k_max: int,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor | None]:
    """Concatenate independent subgraphs into one disjoint (block-diagonal) graph."""
    xs: list[torch.Tensor] = []
    lines: list[torch.Tensor] = []
    pes: list[torch.Tensor] = []
    offset = 0
    for edge_ids in edge_id_groups:
        x, line, pe = _make_batch(graph, edge_ids, rng, use_pe, sign_flip, k_max)
        lines.append(line + offset)
        xs.append(x)
        if pe is not None:
            pes.append(pe)
        offset += x.shape[0]
    return (
        torch.cat(xs, dim=0),
        torch.cat(lines, dim=1),
        torch.cat(pes, dim=0) if pes else None,
    )


def train(
    p: int,
    graphs_dir: Path,
    out_dir: Path,
    epochs: int = 100,
    batch_subgraphs: int = 50,
    max_edges: int = 200,
    lr: float = 1e-3,
    patience: int = 10,
    seed: int = 0,
    k_max: int = 32,
    use_pe: bool = True,
    val_fraction: float = 0.1,
    device: str = "auto",
    batched: bool | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if device == "auto":
        device_obj = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device_obj = torch.device(device)
    if batched is None:
        # GPU benefits from one block-diagonal batch; CPU is faster per subgraph.
        batched = device_obj.type == "cuda"
    graph = load_graph(graphs_dir / f"p{p}" / "train1.npz")

    rng = np.random.default_rng(seed)
    n_edges = graph.y.shape[0]
    permutation = rng.permutation(n_edges)
    n_val = max(1, int(n_edges * val_fraction))
    val_ids = np.sort(permutation[:n_val])
    train_ids = np.sort(permutation[n_val:])

    train_neighbors = _neighbor_lists(graph, train_ids, k_max, seed)
    val_neighbors = _neighbor_lists(graph, val_ids, k_max, seed + 1)

    val_rng = np.random.default_rng(seed + 1)
    val_groups = [
        _sample_subgraph(val_neighbors, val_ids, max_edges, val_rng) for _ in range(10)
    ]
    if batched:
        val_x, val_line, val_pe = _make_batched_batch(
            graph, val_groups, val_rng, use_pe, False, k_max
        )
    else:
        val_batches = [
            _make_batch(graph, ids, val_rng, use_pe, False, k_max)
            for ids in val_groups
        ]

    torch.manual_seed(seed)
    model = GTAE(p, pe_dim=PE_DIM).to(device_obj)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    best_val = float("inf")
    best_state: dict[str, torch.Tensor] | None = None
    bad_epochs = 0
    log_rows: list[dict[str, Any]] = []

    for epoch in range(1, epochs + 1):
        model.train()
        if batched:
            groups = [
                _sample_subgraph(train_neighbors, train_ids, max_edges, rng)
                for _ in range(batch_subgraphs)
            ]
            x, line, pe = _make_batched_batch(graph, groups, rng, use_pe, True, k_max)
            x = x.to(device_obj)
            line = line.to(device_obj)
            if pe is not None:
                pe = pe.to(device_obj)
            reconstructed, _ = model(x, line, pe)
            loss = nn.functional.mse_loss(reconstructed, x)
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_mse = loss.item()
            mask = x != 0
            train_nonzero = (
                (reconstructed.detach() - x)[mask].pow(2).mean().item()
                if mask.any()
                else 0.0
            )
        else:
            train_total = 0.0
            nonzero_total = 0.0
            for _ in range(batch_subgraphs):
                edge_ids = _sample_subgraph(train_neighbors, train_ids, max_edges, rng)
                x, line, pe = _make_batch(graph, edge_ids, rng, use_pe, True, k_max)
                x = x.to(device_obj)
                line = line.to(device_obj)
                if pe is not None:
                    pe = pe.to(device_obj)
                reconstructed, _ = model(x, line, pe)
                loss = nn.functional.mse_loss(reconstructed, x)
                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                train_total += loss.item()
                mask = x != 0
                if mask.any():
                    nonzero_total += (
                        (reconstructed.detach() - x)[mask].pow(2).mean().item()
                    )
            train_mse = train_total / batch_subgraphs
            train_nonzero = nonzero_total / batch_subgraphs

        model.eval()
        with torch.no_grad():
            if batched:
                vx = val_x.to(device_obj)
                vline = val_line.to(device_obj)
                vpe = val_pe.to(device_obj) if val_pe is not None else None
                reconstructed, _ = model(vx, vline, vpe)
                val_mse = nn.functional.mse_loss(reconstructed, vx).item()
            else:
                val_total = 0.0
                for x, line, pe in val_batches:
                    x = x.to(device_obj)
                    line = line.to(device_obj)
                    if pe is not None:
                        pe = pe.to(device_obj)
                    reconstructed, _ = model(x, line, pe)
                    val_total += nn.functional.mse_loss(reconstructed, x).item()
                val_mse = val_total / len(val_batches)

        log_rows.append(
            {
                "epoch": epoch,
                "train_mse": train_mse,
                "train_nonzero_mse": train_nonzero,
                "val_mse": val_mse,
                "lr": lr,
            }
        )
        if val_mse < best_val - 1e-6:
            best_val = val_mse
            best_state = {
                key: value.detach().cpu().clone()
                for key, value in model.state_dict().items()
            }
            bad_epochs = 0
        else:
            bad_epochs += 1
            if bad_epochs >= patience:
                break

    if best_state is None:
        best_state = model.state_dict()
    torch.save(
        {
            "state_dict": best_state,
            "p": p,
            "arch": ARCH[p],
            "pe_dim": PE_DIM,
            "use_pe": use_pe,
        },
        out_dir / "model.pt",
    )
    with open(out_dir / "train_log.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(log_rows[0]))
        writer.writeheader()
        writer.writerows(log_rows)
    config = {
        "p": p,
        "graphs_dir": str(graphs_dir),
        "epochs_run": len(log_rows),
        "batch_subgraphs": batch_subgraphs,
        "max_edges": max_edges,
        "lr": lr,
        "patience": patience,
        "seed": seed,
        "k_max": k_max,
        "use_pe": use_pe,
        "device": str(device_obj),
        "batched": bool(batched),
        "val_fraction": val_fraction,
        "best_val_mse": best_val,
        "train_edges": int(len(train_ids)),
        "val_edges": int(len(val_ids)),
    }
    (out_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p", type=int, required=True)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out", default=None)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-subgraphs", type=int, default=50)
    parser.add_argument("--max-edges", type=int, default=200)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--k-max", type=int, default=32)
    parser.add_argument("--no-pe", action="store_true")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument(
        "--batched",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="one block-diagonal batch (default: on for CUDA, off for CPU)",
    )
    args = parser.parse_args(argv)
    out = Path(args.out or f"experiments/gtae_p{args.p}")
    config = train(
        args.p,
        Path(args.graphs),
        out,
        epochs=args.epochs,
        batch_subgraphs=args.batch_subgraphs,
        max_edges=args.max_edges,
        lr=args.lr,
        patience=args.patience,
        seed=args.seed,
        k_max=args.k_max,
        use_pe=not args.no_pe,
        device=args.device,
        batched=args.batched,
    )
    print(json.dumps(config, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
