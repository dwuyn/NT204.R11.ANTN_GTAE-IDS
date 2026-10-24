#!/usr/bin/env python3
"""Train GTAE for all p/seed combinations; resumable for Kaggle sessions.

    python scripts/train_all.py --graphs data/graphs/T --out experiments/T \
        --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --epochs 100
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.train_gtae import train  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out", default="experiments/T")
    parser.add_argument("--ps", type=int, nargs="+", default=[2, 3, 4, 5, 6, 7, 8])
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-subgraphs", type=int, default=50)
    parser.add_argument("--max-edges", type=int, default=200)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--k-max", type=int, default=32)
    parser.add_argument("--no-pe", action="store_true")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument(
        "--batched", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    run_log = out_root / "runs.jsonl"
    for p in args.ps:
        for seed in args.seeds:
            run_dir = out_root / f"p{p}" / f"seed{seed}"
            if args.resume and (run_dir / "model.pt").exists():
                print(f"skip {run_dir} (model.pt exists)", flush=True)
                continue
            print(f"=== train p={p} seed={seed} -> {run_dir}", flush=True)
            started = time.time()
            config = train(
                p,
                Path(args.graphs),
                run_dir,
                epochs=args.epochs,
                batch_subgraphs=args.batch_subgraphs,
                max_edges=args.max_edges,
                lr=args.lr,
                patience=args.patience,
                seed=seed,
                k_max=args.k_max,
                use_pe=not args.no_pe,
                device=args.device,
                batched=args.batched,
            )
            record = {
                "p": p,
                "seed": seed,
                "elapsed_s": round(time.time() - started, 1),
                **config,
            }
            with open(run_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            print(json.dumps(record), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
