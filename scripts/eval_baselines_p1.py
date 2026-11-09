"""Run Baseline B0, B1, and Proposal P1 experiments and write summary CSVs.

Tasks:
1. B0: Raw feature vector (50*p) + PyOD detectors.
2. B1: MLP-AE (bottleneck latent z=64) + PyOD detectors.
3. P1: Conformal calibration and early-exit sequential testing (p=2..8).
4. Outputs:
   - results/B0_summary.csv
   - results/B1_summary.csv
   - results/P1_summary.csv

Afterwards run ``python scripts/make_p1_report.py`` to regenerate
``reports/P1.md`` from the measurement CSVs.
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
from sklearn.metrics import roc_auc_score, roc_curve
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src.detectors import (
    DETECTOR_NAMES,
    build_detectors,
    fit_detectors,
    metrics,
    predict_detectors,
    rank_normalize,
    vote,
)
from src.early_exit import run_early_exit
from src.embed import embed_graph, load_model
from src.graph_builder import load_graph


class MLPAE(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int = 128, latent_dim: int = 64):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, in_dim),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        z = self.encoder(x)
        out = self.decoder(z)
        return out, z


def run_b0(graphs_dir: Path, ps: tuple[int, ...] = (2, 4, 8), seeds: tuple[int, ...] = (0, 1, 2)) -> list[dict]:
    """B0: Raw feature vector + detectors."""
    records = []
    for p in ps:
        train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
        test = load_graph(graphs_dir / f"p{p}" / "test.npz")
        x_train = train2.edge_attr
        x_test = test.edge_attr
        y_test = test.y.astype(np.int8)
        attack_types = test.attack_type

        for seed in seeds:
            rng = np.random.default_rng(seed)
            perm = rng.permutation(len(x_train))
            n_calib = max(1, int(len(x_train) * 0.2))
            calib_idx = perm[:n_calib]
            fit_idx = perm[n_calib:]

            detectors = build_detectors(contamination=0.01, seed=seed)
            fit_detectors(detectors, x_train[fit_idx])
            preds, scores = predict_detectors(detectors, x_test)
            calib_preds, calib_scores = predict_detectors(detectors, x_train[calib_idx])

            fused = np.mean(
                [
                    rank_normalize(np.concatenate([calib_scores[name], scores[name]]))
                    for name in DETECTOR_NAMES
                ],
                axis=0,
            )
            fused_calib = fused[:n_calib]
            fused_test = fused[n_calib:]

            for name in DETECTOR_NAMES:
                m = metrics(y_test, preds[name], scores[name], calibration_scores=calib_scores[name], attack_types=attack_types)
                records.append({"p": p, "seed": seed, "model": "B0_raw_vector", "rule": name, **m})

            for rule in ("strict", "tie"):
                m = metrics(y_test, vote(preds, rule), fused_test, calibration_scores=fused_calib, attack_types=attack_types)
                records.append({"p": p, "seed": seed, "model": "B0_raw_vector", "rule": f"ensemble_{rule}", **m})
    return records


def run_b1(graphs_dir: Path, ps: tuple[int, ...] = (2, 4, 8), seeds: tuple[int, ...] = (0, 1, 2)) -> list[dict]:
    """B1: MLP-AE latent embeddings + detectors."""
    records = []
    for p in ps:
        train1 = load_graph(graphs_dir / f"p{p}" / "train1.npz")
        train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
        test = load_graph(graphs_dir / f"p{p}" / "test.npz")

        x_train1 = torch.from_numpy(train1.edge_attr).float()
        x_train2 = torch.from_numpy(train2.edge_attr).float()
        x_test = torch.from_numpy(test.edge_attr).float()
        y_test = test.y.astype(np.int8)
        attack_types = test.attack_type
        in_dim = x_train1.shape[1]

        for seed in seeds:
            torch.manual_seed(seed)
            ae = MLPAE(in_dim=in_dim, hidden_dim=128, latent_dim=64)
            opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
            crit = nn.MSELoss()

            loader = DataLoader(TensorDataset(x_train1), batch_size=128, shuffle=True)
            ae.train()
            for _ in range(15):  # 15 epochs
                for (batch_x,) in loader:
                    opt.zero_grad()
                    recon, _ = ae(batch_x)
                    loss = crit(recon, batch_x)
                    loss.backward()
                    opt.step()

            ae.eval()
            with torch.no_grad():
                _, z_train2 = ae(x_train2)
                _, z_test = ae(x_test)
                z_train2 = z_train2.numpy()
                z_test = z_test.numpy()

            rng = np.random.default_rng(seed)
            perm = rng.permutation(len(z_train2))
            n_calib = max(1, int(len(z_train2) * 0.2))
            calib_idx = perm[:n_calib]
            fit_idx = perm[n_calib:]

            detectors = build_detectors(contamination=0.01, seed=seed)
            fit_detectors(detectors, z_train2[fit_idx])
            preds, scores = predict_detectors(detectors, z_test)
            calib_preds, calib_scores = predict_detectors(detectors, z_train2[calib_idx])

            fused = np.mean(
                [
                    rank_normalize(np.concatenate([calib_scores[name], scores[name]]))
                    for name in DETECTOR_NAMES
                ],
                axis=0,
            )
            fused_calib = fused[:n_calib]
            fused_test = fused[n_calib:]

            for name in DETECTOR_NAMES:
                m = metrics(y_test, preds[name], scores[name], calibration_scores=calib_scores[name], attack_types=attack_types)
                records.append({"p": p, "seed": seed, "model": "B1_MLPAE", "rule": name, **m})

            for rule in ("strict", "tie"):
                m = metrics(y_test, vote(preds, rule), fused_test, calibration_scores=fused_calib, attack_types=attack_types)
                records.append({"p": p, "seed": seed, "model": "B1_MLPAE", "rule": f"ensemble_{rule}", **m})
    return records


def run_p1(
    experiments_dir: Path,
    fixed_graphs_dir: Path,
    device: torch.device,
    alphas: tuple[float, ...] = (0.01, 0.05, 0.10),
    seeds: tuple[int, ...] = (0, 1, 2),
    ps: tuple[int, ...] = (2, 3, 4, 5, 6, 7, 8),
    calibration_fraction: float = 0.4,
) -> list[dict]:
    """P1: Sequential Early-Exit evaluation using conformal calibration on T_fixed.

    ``calibration_fraction`` controls the benign split of ``train2`` used to
    estimate conformal p-values. The detector fit uses the remainder. The
    default 0.4 (800 flows of 2,000) is large enough for Bonferroni fusion to
    reach alpha=0.05 across seven packet budgets; 0.2 leaves only 400 flows and
    makes that operating point mathematically unreachable.
    """
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be in (0, 1)")
    records = []

    for seed in seeds:
        print(f"Running P1 for seed {seed} across p=2..8...")
        scores_by_p: dict[int, dict[str, np.ndarray]] = {}
        calib_scores_by_p: dict[int, dict[str, np.ndarray]] = {}
        y_true = None

        for p in ps:
            model_path = experiments_dir / f"p{p}" / f"seed{seed}" / "model.pt"
            train2 = load_graph(fixed_graphs_dir / f"p{p}" / "train2.npz")
            test = load_graph(fixed_graphs_dir / f"p{p}" / "test.npz")

            if y_true is None:
                y_true = test.y.astype(np.int8)

            model, checkpoint = load_model(model_path, device)
            use_pe = bool(checkpoint.get("use_pe", True))

            z_train = embed_graph(model, train2, device, k_max=32, use_pe=use_pe, seed=seed)
            z_test = embed_graph(model, test, device, k_max=32, use_pe=use_pe, seed=seed)

            rng = np.random.default_rng(seed)
            perm = rng.permutation(len(z_train))
            n_calib = max(1, int(len(z_train) * calibration_fraction))
            calib_idx = perm[:n_calib]
            fit_idx = perm[n_calib:]

            detectors = build_detectors(contamination=0.01, seed=seed)
            fit_detectors(detectors, z_train[fit_idx])

            _, scores = predict_detectors(detectors, z_test)
            _, calib_scores = predict_detectors(detectors, z_train[calib_idx])

            scores_by_p[p] = scores
            calib_scores_by_p[p] = calib_scores

        for alpha in alphas:
            for method in ("fisher", "bonferroni"):
                res = run_early_exit(
                    scores_by_p=scores_by_p,
                    calib_scores_by_p=calib_scores_by_p,
                    y_true=y_true,
                    alpha=alpha,
                    method=method,
                    ps=ps,
                )
                # Lowest fused p-value across packet budgets is the P1 anomaly
                # score; use it for threshold-free ranking metrics.
                min_p = np.min(np.vstack([res.fused_pvalues[p] for p in ps]), axis=0)
                ranking_score = 1.0 - min_p
                auroc = float(roc_auc_score(y_true, ranking_score))
                fpr_curve, tpr_curve, _ = roc_curve(y_true, ranking_score)
                idx = int(np.searchsorted(fpr_curve, 0.01, side="right") - 1)
                tpr_at_fpr_1pct = float(tpr_curve[max(idx, 0)])
                records.append({
                    "seed": seed,
                    "alpha": alpha,
                    "method": method,
                    "tpr": round(res.tpr, 4),
                    "fpr": round(res.fpr, 4),
                    "mean_p_attack": round(res.mean_p_attack, 2),
                    "mean_p_benign": round(res.mean_p_benign, 2),
                    "mean_p_total": round(res.mean_p_total, 2),
                    "early_exit_rate_attack": round(res.early_exit_rate_attack, 4),
                    "auroc": round(auroc, 4),
                    "tpr_at_fpr_1pct": round(tpr_at_fpr_1pct, 4),
                })
    return records


# Report generation lives in scripts/make_p1_report.py so the measurement
# CSVs remain the single source of truth. Do not re-add hardcoded tables here.


def _write_csv(path: Path, fieldnames: list[str], records: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key) for key in fieldnames})
    print(f"Saved {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--fixed-graphs", default="data/graphs/T_fixed")
    parser.add_argument("--models", default="experiments/T")
    parser.add_argument("--results", default="results")
    parser.add_argument("--b0-b1-ps", type=int, nargs="+", default=[2, 4, 8])
    parser.add_argument("--p1-ps", type=int, nargs="+", default=[2, 3, 4, 5, 6, 7, 8])
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--alphas", type=float, nargs="+", default=[0.01, 0.05, 0.10])
    parser.add_argument(
        "--calibration-fraction",
        type=float,
        default=0.4,
        help="Fraction of train2 used for P1 conformal calibration (default: 0.4).",
    )
    parser.add_argument(
        "--p1-only",
        action="store_true",
        help="Skip B0/B1 and only regenerate P1_summary.csv.",
    )
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda", "auto"])
    args = parser.parse_args(argv)

    if not 0.0 < args.calibration_fraction < 1.0:
        raise ValueError("--calibration-fraction must be in (0, 1)")

    graphs_dir = Path(args.graphs)
    fixed_graphs_dir = Path(args.fixed_graphs)
    experiments_dir = Path(args.models)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available()
        else "cpu" if args.device == "auto" else args.device
    )

    b0_fields = ["p", "seed", "model", "rule", "tpr", "fpr", "precision", "f1", "auroc", "pr_auc", "tpr_at_fpr", "fpr_at_threshold"]
    if not args.p1_only:
        print("=== Running Baseline B0 (Raw Vector) ===")
        b0_records = run_b0(graphs_dir, ps=tuple(args.b0_b1_ps), seeds=tuple(args.seeds))
        _write_csv(results_dir / "B0_summary.csv", b0_fields, b0_records)

        print("=== Running Baseline B1 (MLP-AE) ===")
        b1_records = run_b1(graphs_dir, ps=tuple(args.b0_b1_ps), seeds=tuple(args.seeds))
        _write_csv(results_dir / "B1_summary.csv", b0_fields, b1_records)

    print("=== Running Proposal P1 (Conformal Early Exit) ===")
    p1_records = run_p1(
        experiments_dir,
        fixed_graphs_dir,
        device=device,
        alphas=tuple(args.alphas),
        seeds=tuple(args.seeds),
        ps=tuple(args.p1_ps),
        calibration_fraction=args.calibration_fraction,
    )
    _write_csv(
        results_dir / "P1_summary.csv",
        ["seed", "alpha", "method", "tpr", "fpr", "mean_p_attack", "mean_p_benign", "mean_p_total", "early_exit_rate_attack", "auroc", "tpr_at_fpr_1pct"],
        p1_records,
    )
    meta = {
        "calibration_fraction": args.calibration_fraction,
        "seeds": list(args.seeds),
        "alphas": list(args.alphas),
        "ps": list(args.p1_ps),
        "train2_edges": 2000,
        "n_calib": int(2000 * args.calibration_fraction),
    }
    (results_dir / "P1_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Saved {results_dir / 'P1_meta.json'}")
    print("Run `python scripts/make_p1_report.py` to regenerate reports/P1.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
