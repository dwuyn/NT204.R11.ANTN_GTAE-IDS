#!/usr/bin/env python3
"""A3 ablation: reconstruction-error detector on frozen GTAE checkpoints.

For each p/seed, reconstruct train2 and test edges with the existing GTAE
decoder, then threshold the per-edge MSE at the 99th percentile of benign
train2 errors. No training is performed.

Usage:
    python scripts/eval_recon_ablation.py \
        --graphs data/graphs/T --models experiments/T \
        --ps 2 4 8 --seeds 0 1 2 --out results
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

from src.detectors import metrics
from src.embed import load_model
from src.graph_builder import load_graph
from src.line_graph import build_line_graph
from src.pe import PE_DIM, edge_pe, laplacian_pe


def _reconstruction_errors(
    model: torch.nn.Module,
    graph,
    device: torch.device,
    k_max: int,
    use_pe: bool,
    seed: int,
) -> np.ndarray:
    line = build_line_graph(
        graph.edge_index, graph.num_nodes, max_neighbors=k_max, seed=seed
    )
    x = torch.from_numpy(graph.edge_attr).to(device)
    line_t = torch.as_tensor(line, dtype=torch.long, device=device)
    pe_t = None
    if use_pe:
        node_pe = laplacian_pe(
            graph.edge_index, graph.num_nodes, k=PE_DIM, seed=seed
        )
        pe_t = torch.from_numpy(edge_pe(node_pe, graph.edge_index)).to(device)

    with torch.no_grad():
        reconstructed, _ = model(x, line_t, pe_t)
        errors = torch.mean((reconstructed - x) ** 2, dim=1).cpu().numpy()
    return errors.astype(np.float64)


def evaluate(
    model_path: Path,
    graphs_dir: Path,
    p: int,
    seed: int,
    device: torch.device,
    k_max: int,
    contamination: float,
) -> dict:
    train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
    test = load_graph(graphs_dir / f"p{p}" / "test.npz")
    model, checkpoint = load_model(model_path, device)
    use_pe = bool(checkpoint.get("use_pe", True))

    train_errors = _reconstruction_errors(
        model, train2, device, k_max, use_pe, seed
    )
    test_errors = _reconstruction_errors(model, test, device, k_max, use_pe, seed)

    threshold = float(np.quantile(train_errors, 1.0 - contamination))
    y_pred = (test_errors > threshold).astype(np.int8)
    result = metrics(
        test.y.astype(np.int8),
        y_pred,
        scores=test_errors,
        calibration_scores=train_errors,
        attack_types=test.attack_type,
    )
    return {
        "p": p,
        "seed": seed,
        "model": "A3_recon_mse",
        "rule": f"threshold_{int(round((1.0 - contamination) * 100))}pct",
        "threshold": threshold,
        "train2_edges": int(len(train_errors)),
        "test_edges": int(len(test_errors)),
        **result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--models", default="experiments/T")
    parser.add_argument("--ps", type=int, nargs="+", default=[2, 4, 8])
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--out", default="results")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument("--k-max", type=int, default=32)
    parser.add_argument("--contamination", type=float, default=0.01)
    args = parser.parse_args(argv)

    if not 0.0 < args.contamination < 1.0:
        raise ValueError("contamination must be in (0, 1)")

    graphs_dir = Path(args.graphs)
    models_dir = Path(args.models)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available()
        else "cpu" if args.device == "auto" else args.device
    )
    print(f"device={device} graphs={graphs_dir} models={models_dir}", flush=True)

    records: list[dict] = []
    for p in args.ps:
        for seed in args.seeds:
            model_path = models_dir / f"p{p}" / f"seed{seed}" / "model.pt"
            if not model_path.exists():
                print(f"skip missing {model_path}", flush=True)
                continue
            print(f"=== recon p={p} seed={seed}", flush=True)
            record = evaluate(
                model_path, graphs_dir, p, seed, device, args.k_max, args.contamination
            )
            records.append(record)
            run_path = out_dir / f"A3_recon_p{p}_seed{seed}.json"
            run_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            print(
                f"  TPR {record['tpr']:.4f} FPR {record['fpr']:.4f} "
                f"AUROC {record['auroc']} TPR@1% {record['tpr_at_fpr']}",
                flush=True,
            )

    if not records:
        raise SystemExit("no runs produced")

    fieldnames = list(records[0].keys())
    csv_path = out_dir / "A3_recon.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    print(f"wrote {len(records)} runs to {csv_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
