"""Quantify F3: the paper tests each attack class on its **own** graph (no benign edges).

``src/eval`` and the paper-parity runs score a *mixed* graph (benign + all attack classes),
which is the deployment situation. The authors' notebook instead calls
``create_graph_from_df`` per class, so a class-only graph carries a different topology
(thousands of edges onto one victim hub) — the candidate shortcut F3 in
``docs/REPRO_AUDIT.md`` §5.2.

This script rebuilds the class-only graphs from an existing test graph and measures, with
the *same* trained encoder and the *same* benign calibration, the anomaly-detection rate
on (a) the class-only graph and (b) the same class's edges inside the mixed graph. No
training happens; only embeddings of subsets.

    python scripts/eval_per_class_graphs.py --p 8 --seeds 0 1 2
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import sys
from collections import defaultdict

import numpy as np
import torch

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.detectors import build_detectors, fit_detectors, predict_detectors, vote  # noqa: E402
from src.embed import embed_graph, load_model  # noqa: E402
from src.graph_builder import GraphArrays, load_graph  # noqa: E402

MIN_EDGES = 10


def _subset(graph: GraphArrays, mask: np.ndarray, label: int) -> GraphArrays:
    """Class-only graph: keep ``mask`` edges, renumber nodes compactly (paper's per-class graph)."""
    edge_index = graph.edge_index[:, mask]
    nodes, inverse = np.unique(edge_index, return_inverse=True)
    return GraphArrays(
        edge_index=inverse.reshape(2, -1).astype(np.int32),
        edge_attr=graph.edge_attr[mask],
        y=np.full(int(mask.sum()), label, dtype=np.int8),
        flow_id=graph.flow_id[mask],
        attack_type=graph.attack_type[mask],
        day=graph.day[mask],
        num_nodes=int(nodes.size),
        p=graph.p,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/P_paper")
    parser.add_argument("--models", default="experiments/P_paper")
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--out", default="results/per_class_graphs.csv")
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args(argv)

    device = torch.device(args.device)
    train2 = load_graph(pathlib.Path(args.graphs) / f"p{args.p}" / "train2.npz")
    test = load_graph(pathlib.Path(args.graphs) / f"p{args.p}" / "test.npz")
    classes = sorted({str(t) for t in test.attack_type if t})

    rows: list[dict] = []
    for seed in args.seeds:
        model_path = pathlib.Path(args.models) / f"p{args.p}" / f"seed{seed}" / "model.pt"
        model, _ = load_model(model_path, device)
        z_train = embed_graph(model, train2, device, k_max=32, use_pe=True, seed=seed)
        rng = np.random.default_rng(seed)
        permutation = rng.permutation(len(z_train))
        n_calib = max(1, int(len(z_train) * 0.2))
        fitted = build_detectors(contamination=0.01, seed=seed)
        fit_detectors(fitted, z_train[permutation[n_calib:]])
        z_test = embed_graph(model, test, device, k_max=32, use_pe=True, seed=seed)
        preds, _ = predict_detectors(fitted, z_test)
        tie = vote(preds, "tie")
        for attack in classes:
            mask = np.asarray([str(t) == attack for t in test.attack_type])
            n_mixed = int(mask.sum())
            if n_mixed < MIN_EDGES:
                continue
            sub = _subset(test, mask, label=1)
            z_sub = embed_graph(model, sub, device, k_max=32, use_pe=True, seed=seed)
            preds_sub, _ = predict_detectors(fitted, z_sub)
            tie_sub = vote(preds_sub, "tie")
            row = {
                "p": args.p,
                "seed": seed,
                "attack_type": attack,
                "n_edges": n_mixed,
                "nodes_class_graph": sub.num_nodes,
                "tpr_class_graph": float(np.mean(tie_sub == 1)),
                "tpr_mixed_graph": float(np.mean(tie[mask] == 1)),
            }
            for name in preds:
                row[f"tpr_class_{name}"] = float(np.mean(preds_sub[name] == 1))
                row[f"tpr_mixed_{name}"] = float(np.mean(preds[name][mask] == 1))
            rows.append(row)
            print(
                f"seed {seed} {attack:28s} n={n_mixed:5d} "
                f"class-graph {100 * row['tpr_class_graph']:6.2f}%  "
                f"mixed {100 * row['tpr_mixed_graph']:6.2f}%",
                flush=True,
            )

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nwrote {len(rows)} rows to {out}")

    agg: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for row in rows:
        agg[row["attack_type"]].append((row["tpr_class_graph"], row["tpr_mixed_graph"]))
    print(f"\n{'attack':28s} {'n':>6} {'class-graph':>12} {'mixed':>8} {'delta':>8}")
    for attack in sorted(agg):
        pairs = agg[attack]
        class_tpr = 100 * float(np.mean([c for c, _ in pairs]))
        mixed_tpr = 100 * float(np.mean([m for _, m in pairs]))
        print(f"{attack:28s} {len(pairs):>6} {class_tpr:11.2f}% {mixed_tpr:7.2f}% {class_tpr - mixed_tpr:+7.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
