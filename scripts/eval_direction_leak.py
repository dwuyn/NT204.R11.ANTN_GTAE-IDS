#!/usr/bin/env python3
"""Quantify the direction-encoding asymmetry in the authors' published pipeline.

Published extractor (``jalalgh7/robust-and-real-time-NIDS``, ``*_Packet_Level_Data``):
every packet that is not inside an attack window / attacker-victim pair gets
``Direction = 'unknown'``. Published graph preparation
(``jalalgh7/graph-representation-learning-for-NIDS``, ``*_data_preparation_gnn``):
a packet is written into the forward half only when ``Direction == 'fwd'``,
otherwise into the backward half. Benign traffic is therefore encoded with all
25 header bytes in the backward half of every 50-d packet block, while attack
traffic keeps a fwd/bwd split. A detector can separate the two populations from
that positional pattern alone, without any graph learning.

This script reproduces the effect on *our* graphs (which use a uniform direction
rule for both classes): benign edges are rewritten to the authors' benign
encoding (move every packet to the backward half), attack edges are untouched.
It then runs the authors' four detectors and contamination values
(OCSVM 0.06, IForest/HBOS/INNE 0.09, StandardScaler on the benign training
matrix) and reports per-class detection rates plus a one-bit rule
("any non-zero forward half -> attack").

    python scripts/eval_direction_leak.py --graphs data/graphs/P_paper \
        --out results/direction_leak.csv
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

DETECTOR_NAMES = ("OCSVM", "IForest", "HBOS", "INNE")
CONTAMINATION = {"OCSVM": 0.06, "IForest": 0.09, "HBOS": 0.09, "INNE": 0.09}
FIELDS = ["protocol", "class", "n", "fwd_nonempty", *DETECTOR_NAMES, "ensemble"]


def authors_benign_encoding(x: np.ndarray, y: np.ndarray, p: int) -> np.ndarray:
    """Move every benign packet to the backward half, as the authors' prep does."""
    blocks = x.reshape(len(x), p, 50).copy()
    benign = y == 0
    forward = blocks[benign, :, :25].copy()
    backward = blocks[benign, :, 25:].copy()
    blocks[benign, :, :25] = 0.0
    blocks[benign, :, 25:] = forward + backward
    return blocks.reshape(len(x), 50 * p)


def forward_nonempty(x: np.ndarray, p: int) -> np.ndarray:
    blocks = x.reshape(len(x), p, 50)
    return (blocks[:, :, :25].sum(axis=2) > 0).any(axis=1)


def fit_predict(xtr: np.ndarray, xte: np.ndarray, seed: int) -> dict[str, np.ndarray]:
    from pyod.models.hbos import HBOS
    from pyod.models.iforest import IForest
    from pyod.models.inne import INNE
    from pyod.models.ocsvm import OCSVM
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler().fit(xtr)
    xtr, xte = scaler.transform(xtr), scaler.transform(xte)
    models = {
        "OCSVM": OCSVM(nu=0.05, contamination=CONTAMINATION["OCSVM"]),
        "IForest": IForest(contamination=CONTAMINATION["IForest"], random_state=seed),
        "HBOS": HBOS(contamination=CONTAMINATION["HBOS"]),
        "INNE": INNE(contamination=CONTAMINATION["INNE"], random_state=seed),
    }
    predictions = {}
    for name, model in models.items():
        model.fit(xtr)
        predictions[name] = (model.predict(xte) == 1).astype(np.int8)
    votes = np.sum([predictions[name] for name in DETECTOR_NAMES], axis=0)
    predictions["ensemble"] = (votes >= 1).astype(np.int8)
    return predictions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", default=["data/graphs/P_paper", "data/graphs/T"])
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="results/direction_leak.csv")
    parser.add_argument(
        "--votes-out", default="results/direction_leak_votes.csv",
        help="vote-threshold sweep (>=1..4 detectors) under the same encoding",
    )
    parser.add_argument("--vote-seeds", type=int, nargs="+", default=[0, 1, 2])
    args = parser.parse_args(argv)

    rows: list[dict] = []
    vote_rows: list[dict] = []
    for graphs in args.graphs:
        train = load_graph(Path(graphs) / f"p{args.p}" / "train1.npz")
        test = load_graph(Path(graphs) / f"p{args.p}" / "test.npz")
        y_train = train.y.astype(np.int8)
        y = test.y.astype(np.int8)
        attack_type = test.attack_type.astype(str)
        protocol = Path(graphs).name

        xtr = authors_benign_encoding(train.edge_attr.astype(np.float64), y_train, args.p)
        xte = authors_benign_encoding(test.edge_attr.astype(np.float64), y, args.p)
        predictions = fit_predict(xtr, xte, args.seed)
        fwd = forward_nonempty(xte, args.p)

        for vote_seed in args.vote_seeds:
            vote_pred = (
                predictions
                if vote_seed == args.seed
                else fit_predict(xtr, xte, vote_seed)
            )
            votes = np.sum([vote_pred[name] for name in DETECTOR_NAMES], axis=0)
            for min_votes in (1, 2, 3, 4):
                alert = votes >= min_votes
                vote_rows.append(
                    {
                        "protocol": protocol,
                        "seed": vote_seed,
                        "min_votes": min_votes,
                        "fpr": float(alert[y == 0].mean()),
                        "tpr": float(alert[y == 1].mean()),
                    }
                )

        groups = [("Benign", y == 0)]
        for attack in sorted(set(attack_type[y == 1])):
            groups.append((attack, (y == 1) & (attack_type == attack)))
        for name, mask in groups:
            rows.append(
                {
                    "protocol": protocol,
                    "class": name,
                    "n": int(mask.sum()),
                    "fwd_nonempty": float(fwd[mask].mean()),
                    **{d: float(predictions[d][mask].mean()) for d in DETECTOR_NAMES},
                    "ensemble": float(predictions["ensemble"][mask].mean()),
                }
            )
        benign = y == 0
        print(
            f"{protocol}: one-bit forward-half rule "
            f"TPR {100 * fwd[y == 1].mean():.1f}% / FPR {100 * fwd[benign].mean():.1f}%; "
            f"ensemble TPR {100 * predictions['ensemble'][y == 1].mean():.1f}% / "
            f"FPR {100 * predictions['ensemble'][benign].mean():.1f}%",
            flush=True,
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    votes_out = Path(args.votes_out)
    with votes_out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["protocol", "seed", "min_votes", "fpr", "tpr"]
        )
        writer.writeheader()
        writer.writerows(vote_rows)
    for row in vote_rows:
        print(
            f"{row['protocol']} seed{row['seed']} votes>={row['min_votes']}: "
            f"FPR {100 * row['fpr']:.2f}% TPR {100 * row['tpr']:.2f}%",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
