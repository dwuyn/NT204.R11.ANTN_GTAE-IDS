"""Train GTAE on the full train1 graph (no subgraph sampling).

This tests whether the 200-edge subgraph assumption is the bottleneck: the model
sees the whole benign graph, and LapPE/line-graph are computed once on it.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import torch
from torch import nn

from src.graph_builder import load_graph
from src.line_graph import build_line_graph
from src.model_gtae import ARCH, GTAE
from src.pe import PE_DIM, edge_pe, laplacian_pe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p", type=int, required=True)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--k-max", type=int, default=64)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--device", default="cpu", choices=["auto", "cpu", "cuda"])
    args = parser.parse_args(argv)

    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available() else
        "cpu" if args.device == "auto" else args.device
    )
    graph = load_graph(Path(args.graphs) / f"p{args.p}" / "train1.npz")
    line = build_line_graph(
        graph.edge_index, graph.num_nodes, max_neighbors=args.k_max, seed=args.seed
    )
    pe = edge_pe(
        laplacian_pe(graph.edge_index, graph.num_nodes, k=PE_DIM, seed=args.seed),
        graph.edge_index,
    )
    x = torch.from_numpy(graph.edge_attr).to(device)
    line_t = torch.as_tensor(line, dtype=torch.long, device=device)
    pe_t = torch.from_numpy(pe).to(device)

    rng = np.random.default_rng(args.seed)
    perm = rng.permutation(len(x))
    n_val = max(1, int(0.1 * len(x)))
    val_idx = torch.as_tensor(np.sort(perm[:n_val]), device=device)
    train_idx = torch.as_tensor(np.sort(perm[n_val:]), device=device)
    train_mask = torch.zeros(len(x), dtype=torch.bool, device=device)
    val_mask = torch.zeros(len(x), dtype=torch.bool, device=device)
    train_mask[train_idx] = True
    val_mask[val_idx] = True

    torch.manual_seed(args.seed)
    model = GTAE(args.p, pe_dim=PE_DIM).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    best_val = float("inf")
    best_state = None
    rows = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        reconstructed, _ = model(x, line_t, pe_t)
        train_loss = nn.functional.mse_loss(reconstructed[train_mask], x[train_mask])
        optimizer.zero_grad()
        train_loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        model.eval()
        with torch.no_grad():
            reconstructed, _ = model(x, line_t, pe_t)
            val_loss = nn.functional.mse_loss(reconstructed[val_mask], x[val_mask]).item()
        rows.append({"epoch": epoch, "train_mse": train_loss.item(), "val_mse": val_loss})
        if val_loss < best_val - 1e-6:
            best_val = val_loss
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        if epoch % 10 == 0:
            print(f"epoch {epoch} train {train_loss.item():.5f} val {val_loss:.5f}", flush=True)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": best_state,
            "p": args.p,
            "arch": ARCH[args.p],
            "pe_dim": PE_DIM,
            "use_pe": True,
            "k_max": args.k_max,
            "full_graph": True,
        },
        out / "model.pt",
    )
    with open(out / "train_log.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    config = {
        "p": args.p,
        "graphs_dir": args.graphs,
        "epochs": args.epochs,
        "lr": args.lr,
        "k_max": args.k_max,
        "seed": args.seed,
        "device": str(device),
        "best_val_mse": best_val,
        "edges": int(len(x)),
        "nodes": graph.num_nodes,
        "full_graph": True,
    }
    (out / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(json.dumps(config, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
