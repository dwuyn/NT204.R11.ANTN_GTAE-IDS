"""Evaluate GTAE + detectors for every p/seed (design doc §4.8, D3/D4)."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
import torch

from src.detectors import (
    DETECTOR_NAMES,
    build_detectors,
    fit_detectors,
    metrics,
    predict_detectors,
    rank_normalize,
    vote,
)
from src.embed import embed_graph, load_model
from src.graph_builder import load_graph


def evaluate_model(
    model_path: Path,
    graphs_dir: Path,
    p: int,
    seed: int,
    out_dir: Path,
    device: torch.device,
    contamination: float = 0.01,
    calibration_fraction: float = 0.2,
    k_max: int = 32,
) -> dict:
    train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
    test = load_graph(graphs_dir / f"p{p}" / "test.npz")
    model, checkpoint = load_model(model_path, device)
    use_pe = bool(checkpoint.get("use_pe", True))

    z_train = embed_graph(model, train2, device, k_max=k_max, use_pe=use_pe, seed=seed)
    z_test = embed_graph(model, test, device, k_max=k_max, use_pe=use_pe, seed=seed)

    rng = np.random.default_rng(seed)
    permutation = rng.permutation(len(z_train))
    n_calib = max(1, int(len(z_train) * calibration_fraction))
    calibration_idx = permutation[:n_calib]
    fit_idx = permutation[n_calib:]

    detectors = build_detectors(contamination=contamination, seed=seed)
    fit_detectors(detectors, z_train[fit_idx])

    predictions, scores = predict_detectors(detectors, z_test)
    calib_predictions, calib_scores = predict_detectors(detectors, z_train[calibration_idx])

    # Rank-normalise each detector over calibration+test for a consistent fusion.
    fused = np.mean(
        [
            rank_normalize(np.concatenate([calib_scores[name], scores[name]]))
            for name in DETECTOR_NAMES
        ],
        axis=0,
    )
    fused_calib = fused[:n_calib]
    fused_test = fused[n_calib:]

    y = test.y.astype(np.int8)
    attack_types = test.attack_type
    result: dict = {
        "p": p,
        "seed": seed,
        "model": str(model_path),
        "graph_nodes": int(test.num_nodes),
        "test_edges": int(test.y.size),
        "train2_edges": int(train2.y.size),
        "calibration_edges": int(n_calib),
        "device": str(device),
        "use_pe": use_pe,
        "detectors": {},
        "ensembles": {},
    }
    for name in DETECTOR_NAMES:
        result["detectors"][name] = metrics(
            y,
            predictions[name],
            scores[name],
            calibration_scores=calib_scores[name],
            attack_types=attack_types,
        )
    for rule in ("strict", "tie"):
        result["ensembles"][rule] = metrics(
            y,
            vote(predictions, rule),
            fused_test,
            calibration_scores=fused_calib,
            attack_types=attack_types,
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"M1_p{p}_seed{seed}.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return result


def _summary_row(result: dict, detector: str, prefix: str) -> dict:
    m = result["detectors"][detector] if prefix == "detector" else result["ensembles"][detector]
    return {
        "p": result["p"],
        "seed": result["seed"],
        "model": prefix,
        "detector": detector,
        "tpr": m["tpr"],
        "fpr": m["fpr"],
        "precision": m["precision"],
        "f1": m["f1"],
        "auroc": m["auroc"],
        "pr_auc": m["pr_auc"],
        "tpr_at_fpr_1pct": m["tpr_at_fpr"],
        "fpr_at_threshold": m["fpr_at_threshold"],
        "tp": m["tp"],
        "fp": m["fp"],
        "tn": m["tn"],
        "fn": m["fn"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", default="experiments/T")
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out", default="results")
    parser.add_argument("--ps", type=int, nargs="+", default=[2, 3, 4, 5, 6, 7, 8])
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--calibration-fraction", type=float, default=0.2)
    parser.add_argument("--k-max", type=int, default=32)
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    args = parser.parse_args(argv)

    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available() else
        "cpu" if args.device == "auto" else args.device
    )
    out_dir = Path(args.out)
    models_dir = Path(args.models)
    graphs_dir = Path(args.graphs)
    rows: list[dict] = []

    for p in args.ps:
        for seed in args.seeds:
            model_path = models_dir / f"p{p}" / f"seed{seed}" / "model.pt"
            if not model_path.exists():
                print(f"skip missing {model_path}", flush=True)
                continue
            print(f"=== eval p={p} seed={seed}", flush=True)
            result = evaluate_model(
                model_path,
                graphs_dir,
                p,
                seed,
                out_dir,
                device,
                contamination=args.contamination,
                calibration_fraction=args.calibration_fraction,
                k_max=args.k_max,
            )
            for name in DETECTOR_NAMES:
                rows.append(_summary_row(result, name, "detector"))
            for rule in ("strict", "tie"):
                rows.append(_summary_row(result, rule, "ensemble"))

    if rows:
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "M1_summary.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(f"wrote {len(rows)} summary rows to {out_dir / 'M1_summary.csv'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
