#!/usr/bin/env python3
"""A5 header-hygiene ablation: zero TTL + IP/TCP checksums, retrain, re-evaluate.

    python scripts/eval_hygiene.py --ps 8 --seeds 0 1 2 --device cpu

Motivation: three of the 25 kept bytes depend on the addresses/ports (IP and TCP
checksums) or on the path (TTL), so an anomaly detector could exploit them as an
identity shortcut instead of learning header behaviour. This ablation removes
exactly those bytes (`src.packet_encoder.HYGIENE_POSITIONS`), retrains p8 with the
same recipe as M1, and re-runs the standard detector evaluation.

Writes:
  - data/graphs/T_hygiene/p{p}/{train1,train2,test}.npz   (masked copies)
  - experiments/T_hygiene/p{p}/seed{s}/model.pt
  - results/A5/p{p}_seed{s}.json                          (per-run detail)
  - results/A5_hygiene.csv                                (M1_summary schema)
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import replace
from pathlib import Path

import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.detectors import DETECTOR_NAMES  # noqa: E402
from src.eval import evaluate_model  # noqa: E402
from src.graph_builder import load_graph, save_graph  # noqa: E402
from src.packet_encoder import HYGIENE_POSITIONS, apply_hygiene  # noqa: E402
from src.train_gtae import train  # noqa: E402

SPLITS = ("train1", "train2", "test")


def build_masked_graphs(src: Path, dst: Path, ps: list[int]) -> None:
    for p in ps:
        for split in SPLITS:
            source = src / f"p{p}" / f"{split}.npz"
            if not source.exists():
                raise FileNotFoundError(source)
            graph = load_graph(source)
            masked = replace(graph, edge_attr=apply_hygiene(graph.edge_attr, p))
            target = dst / f"p{p}" / f"{split}.npz"
            save_graph(masked, target)
            changed = int((graph.edge_attr != masked.edge_attr).sum())
            print(
                f"[hygiene] {target.relative_to(REPO_ROOT)}: "
                f"{masked.edge_attr.shape[0]} edges, {changed} values zeroed",
                flush=True,
            )


def summary_rows(result: dict) -> list[dict]:
    rows = []
    for model, key in (("detector", "detectors"), ("ensemble", "ensembles")):
        for name, metrics in result[key].items():
            rows.append(
                {
                    "p": result["p"],
                    "seed": result["seed"],
                    "model": model,
                    "detector": name,
                    "tpr": metrics["tpr"],
                    "fpr": metrics["fpr"],
                    "precision": metrics["precision"],
                    "f1": metrics["f1"],
                    "auroc": metrics["auroc"],
                    "pr_auc": metrics["pr_auc"],
                    "tpr_at_fpr_1pct": metrics["tpr_at_fpr"],
                    "fpr_at_threshold": metrics["fpr_at_threshold"],
                    "tp": metrics["tp"],
                    "fp": metrics["fp"],
                    "tn": metrics["tn"],
                    "fn": metrics["fn"],
                }
            )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out-graphs", default="data/graphs/T_hygiene")
    parser.add_argument("--out-models", default="experiments/T_hygiene")
    parser.add_argument("--results", default="results")
    parser.add_argument("--ps", type=int, nargs="+", default=[8])
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--patience", type=int, default=100)
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--device", default="cpu", choices=["auto", "cpu", "cuda"])
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    src = REPO_ROOT / args.graphs
    graph_dir = REPO_ROOT / args.out_graphs
    model_root = REPO_ROOT / args.out_models
    results = REPO_ROOT / args.results
    json_dir = results / "A5"
    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available() else
        ("cpu" if args.device == "auto" else args.device)
    )
    print(f"[hygiene] zeroing bytes {HYGIENE_POSITIONS} of every 25-byte packet", flush=True)

    build_masked_graphs(src, graph_dir, args.ps)

    rows: list[dict] = []
    for p in args.ps:
        for seed in args.seeds:
            run_dir = model_root / f"p{p}" / f"seed{seed}"
            model_path = run_dir / "model.pt"
            if args.resume and model_path.exists():
                print(f"[hygiene] reuse {model_path}", flush=True)
            else:
                print(f"[hygiene] train p={p} seed={seed} -> {run_dir}", flush=True)
                train(
                    p,
                    graph_dir,
                    run_dir,
                    epochs=args.epochs,
                    patience=args.patience,
                    seed=seed,
                    device=args.device,
                )
            result = evaluate_model(
                model_path,
                graph_dir,
                p,
                seed,
                json_dir,
                device,
                contamination=args.contamination,
            )
            # evaluate_model names the file M1_p{p}_seed{s}; keep A5 distinct.
            produced = json_dir / f"M1_p{p}_seed{seed}.json"
            if produced.exists():
                produced.replace(json_dir / f"A5_p{p}_seed{seed}.json")
            rows.extend(summary_rows(result))

    out_csv = results / "A5_hygiene.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    ensemble = [r for r in rows if r["model"] == "ensemble" and r["detector"] == "tie"]
    for p in args.ps:
        group = [r for r in ensemble if r["p"] == p]
        if not group:
            continue
        mean = lambda key: sum(float(r[key]) for r in group) / len(group)  # noqa: E731
        print(
            f"[hygiene] p={p} ensemble tie: TPR {100 * mean('tpr'):.2f}% "
            f"FPR {100 * mean('fpr'):.2f}% AUROC {mean('auroc'):.4f} "
            f"(n={len(group)})",
            flush=True,
        )
    print(f"[hygiene] wrote {out_csv.relative_to(REPO_ROOT)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
