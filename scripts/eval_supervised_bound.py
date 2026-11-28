#!/usr/bin/env python3
"""Supervised probe on the same edge features: same-day vs cross-day split.

The paper's operating point is TPR 99.04% at FPR 6.56% (Table VI). This script
measures what a *supervised* classifier (RandomForest) can do on the exact
400-d edge vectors that feed GTAE, under the two split regimes:

* ``same_day``: Friday edges (benign + attack) split 70/30 at random - the
  authors' benign train/test protocol (F4), with labels available;
* ``cross_day``: train on Tuesday+Wednesday edges, test on Thursday+Friday -
  the closest supervised analogue of the leak-free protocol ``T``.

It also repeats both with the frozen GTAE bottleneck ``z`` to show whether the
representation, not the classifier, is the binding constraint. These are
supervised probes, not a strict upper bound (an unsupervised detector can beat
the RF on raw features); labels for the test day are used for training, which
the paper's one-class setting never does.

    python scripts/eval_supervised_bound.py --graphs data/graphs/T \
        --out results/supervised_bound.csv --seeds 0 1 2 --device cpu
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.graph_builder import load_graph  # noqa: E402

FIELDS = [
    "scenario",
    "features",
    "seed",
    "train_edges",
    "test_edges",
    "test_benign",
    "test_attack",
    "auroc",
    "tpr_at_test_fpr_6.56pct",
    "tpr_at_test_fpr_1pct",
    "fpr_at_threshold",
]


def _tpr_at_test_fpr(y: np.ndarray, scores: np.ndarray, target: float) -> float:
    benign = scores[y == 0]
    positives = scores[y == 1]
    threshold = float(np.quantile(benign, 1.0 - target))
    return float((positives >= threshold).mean())


def _fit_predict(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    seed: int,
) -> dict[str, float]:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score

    clf = RandomForestClassifier(
        n_estimators=300, n_jobs=-1, random_state=seed, min_samples_leaf=1
    )
    clf.fit(x_train, y_train)
    scores = clf.predict_proba(x_test)[:, 1]
    return {
        "auroc": float(roc_auc_score(y_test, scores)),
        "tpr_at_test_fpr_6.56pct": _tpr_at_test_fpr(y_test, scores, 0.0656),
        "tpr_at_test_fpr_1pct": _tpr_at_test_fpr(y_test, scores, 0.01),
    }


def scenarios(day: np.ndarray, y: np.ndarray, seed: int) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    rng = np.random.default_rng(seed)
    friday = day == "friday"
    # same-day: 70/30 random split of every Friday edge (benign and attack)
    ids = np.flatnonzero(friday)
    rng.shuffle(ids)
    cut = int(round(0.7 * len(ids)))
    same_train = np.zeros_like(friday)
    same_test = np.zeros_like(friday)
    same_train[ids[:cut]] = True
    same_test[ids[cut:]] = True
    # cross-day: Tue+Wed -> Thu+Fri
    early = (day == "tuesday") | (day == "wednesday")
    late = (day == "thursday") | (day == "friday")
    return {"same_day": (same_train, same_test), "cross_day": (early, late)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--out", default="results/supervised_bound.csv")
    parser.add_argument(
        "--embedding-template",
        default=None,
        help="optional path template with {seed} for a test-edge z npz",
    )
    args = parser.parse_args(argv)

    graph = load_graph(Path(args.graphs) / f"p{args.p}" / "test.npz")
    raw = graph.edge_attr.astype(np.float32)
    y = graph.y.astype(np.int8)
    day = graph.day.astype(str)
    rows: list[dict] = []
    for seed in args.seeds:
        features = {"raw": raw}
        if args.embedding_template:
            path = Path(args.embedding_template.format(seed=seed))
            z = np.load(path)["z"].astype(np.float32)
            if len(z) != len(y):
                raise SystemExit(f"{path}: embedding rows {len(z)} != test edges {len(y)}")
            features["z"] = z
        for scenario, (train_mask, test_mask) in scenarios(day, y, seed).items():
            for name, x in features.items():
                result = _fit_predict(
                    x[train_mask],
                    y[train_mask].astype(np.int64),
                    x[test_mask],
                    y[test_mask],
                    seed,
                )
                rows.append(
                    {
                        "scenario": scenario,
                        "features": name,
                        "seed": seed,
                        "train_edges": int(train_mask.sum()),
                        "test_edges": int(test_mask.sum()),
                        "test_benign": int((y[test_mask] == 0).sum()),
                        "test_attack": int((y[test_mask] == 1).sum()),
                        **result,
                        "fpr_at_threshold": 0.0656,
                    }
                )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(
            f"{row['scenario']:9s} {row['features']:4s} seed{row['seed']}  "
            f"AUROC {row['auroc']:.3f}  TPR@6.56% {100*row['tpr_at_test_fpr_6.56pct']:.1f}%  "
            f"TPR@1% {100*row['tpr_at_test_fpr_1pct']:.1f}%",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
