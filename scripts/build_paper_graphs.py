#!/usr/bin/env python3
"""Build the paper-faithful ``P_paper`` graphs from CICFlowMeter CSV rows.

    python scripts/build_paper_graphs.py --out data/graphs/P_paper --ps 8 --seed 0

Never writes into ``data/graphs/T``/``R``/``T_fixed``: ``P_paper`` is a separate,
additional protocol used only for the paper-parity comparison.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.cic_graph import build_paper_graphs  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="data/graphs/P_paper")
    parser.add_argument("--ps", type=int, nargs="+", default=[8])
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--csv-dir", default=None)
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.resolve() in {
        (REPO_ROOT / "data/graphs/T").resolve(),
        (REPO_ROOT / "data/graphs/R").resolve(),
        (REPO_ROOT / "data/graphs/T_fixed").resolve(),
    }:
        parser.error(f"refusing to overwrite the clean protocol graphs at {out}")

    summary = build_paper_graphs(out, ps=args.ps, seed=args.seed, csv_dir=args.csv_dir)
    print(json.dumps(summary["graphs"], indent=2, sort_keys=True), flush=True)
    if summary["shortfall"]:
        print(
            "unattainable paper counts (CSV pool exhausted): "
            + json.dumps(summary["shortfall"], sort_keys=True),
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
