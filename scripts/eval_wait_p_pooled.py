#!/usr/bin/env python3
"""Pooled per-flow wait/delay statistics (the numbers a deployment sees).

``scripts/eval_wait_p.py`` writes one row per (day, group, attack_type, p); its
group medians are therefore *per-day* medians. A table that then takes the
median across days answers "a typical day", not "a typical flow". This script
pools the per-flow delays across all five days and writes
``results/wait_p_pooled.csv`` with the flow-level median and p95.

    python scripts/eval_wait_p_pooled.py --out results/wait_p_pooled.csv
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.eval_wait_p import DAYS, PS, _per_flow_times, _quantile  # noqa: E402

import pyarrow.parquet as pq  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--out", default="results/wait_p_pooled.csv")
    args = parser.parse_args(argv)
    processed = pathlib.Path(args.processed)

    delays: dict[tuple[str, str, int], list[np.ndarray]] = {}
    totals: dict[tuple[str, str, int], int] = {}
    for day in DAYS:
        flows = pq.read_table(
            processed / f"flows_{day}_labeled.parquet",
            columns=["flow_id", "t_last", "n_pkts_total", "label", "attack_type"],
        )
        pkts = pq.read_table(
            processed / f"packets_{day}.parquet", columns=["flow_id", "pkt_idx", "ts"]
        )
        fid = flows.column("flow_id").to_numpy()
        t_last = flows.column("t_last").to_numpy().astype(np.float64)
        label = flows.column("label").to_numpy()
        atype = np.asarray(flows.column("attack_type").to_pylist(), dtype=object)
        order = np.argsort(fid, kind="stable")
        fid, t_last, label, atype = fid[order], t_last[order], label[order], atype[order]

        pfid = pkts.column("flow_id").to_numpy()
        pidx = pkts.column("pkt_idx").to_numpy()
        pts = pkts.column("ts").to_numpy().astype(np.float64)
        order = np.lexsort((pidx, pfid))
        pfid, pidx, pts = pfid[order], pidx[order], pts[order]

        t1, tp = _per_flow_times(fid, pfid, pidx, pts)
        t1 = np.where(np.isnan(t1), t_last, t1)

        groups: list[tuple[str, str, np.ndarray]] = [
            ("benign", "", label == 0),
            ("attack", "", label == 1),
        ]
        for name in sorted({str(a) for a, lab in zip(atype, label) if lab == 1 and str(a)}):
            groups.append(("attack", name, (label == 1) & np.array([str(a) == name for a in atype])))

        for group, attack, mask in groups:
            if not mask.any():
                continue
            for p in PS:
                delay = np.where(np.isnan(tp[p]), t_last - t1, tp[p] - t1)[mask]
                key = (group, attack, p)
                delays.setdefault(key, []).append(delay)
                totals[key] = totals.get(key, 0) + int(mask.sum())

    rows = []
    for (group, attack, p), chunks in sorted(delays.items()):
        values = np.concatenate(chunks)
        rows.append(
            {
                "group": group,
                "attack_type": attack,
                "p": p,
                "n_flows": totals[(group, attack, p)],
                "median_delay_s": float(np.median(values)),
                "p95_delay_s": _quantile(np.sort(values), 0.95),
            }
        )

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["group", "attack_type", "p", "n_flows", "median_delay_s", "p95_delay_s"]
        )
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        if row["p"] == 8 and row["attack_type"] == "":
            print(
                f"{row['group']}: n={row['n_flows']} median {row['median_delay_s']:.3f} s "
                f"p95 {row['p95_delay_s']:.2f} s",
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
