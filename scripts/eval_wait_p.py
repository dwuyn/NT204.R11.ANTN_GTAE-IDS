"""Measure the wall-clock wait for the first ``p`` packets of a flow (P3).

``wait_p = t_p - t_1`` is the time a detector must sit on a flow before it can use the
p-packet snapshot the GTAE pipeline assumes. The paper's MDT (1.28 us/packet) excludes that
wait, and the pipeline's APD counts packets, not seconds. This script puts both in one unit.

Inputs: ``data/processed/packets_{day}.parquet`` (``flow_id, pkt_idx, ts``) and
``data/processed/flows_{day}_labeled.parquet`` (``flow_id, t_last, n_pkts_total, label,
attack_type``).

Two numbers per (group, p):
  * ``wait_p``  = t_p - t_1, defined only for flows that reach p packets (``coverage`` says
    how many do);
  * ``delay_p`` = t_p - t_1 if the flow reaches p packets, else t_last - t_1, because short
    flows are zero-padded and cannot be scored before the flow closes. ``delay_p`` is defined
    for every flow and is what a deployed detector actually experiences.

Output: ``results/wait_p.csv``, one row per (day, group, attack_type, p)::

    day,group,attack_type,p,n_flows_total,n_with_p,coverage,median_s,mean_s,p95_s,max_s,
    median_delay_s,p95_delay_s
"""

from __future__ import annotations

import argparse
import csv
import math
import pathlib

import numpy as np
import pyarrow.parquet as pq

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
PS = tuple(range(2, 9))
FIELDS = [
    "day", "group", "attack_type", "p", "n_flows_total", "n_with_p", "coverage",
    "median_s", "mean_s", "p95_s", "max_s", "median_delay_s", "p95_delay_s",
]


def _quantile(sorted_vals: np.ndarray, q: float) -> float:
    if sorted_vals.size == 0:
        return float("nan")
    pos = q * (sorted_vals.size - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    return float(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo))


def _per_flow_times(fid: np.ndarray, pfid: np.ndarray, pidx: np.ndarray, pts: np.ndarray):
    """Return (t1, {p: t_p_array}) aligned to the flow table."""

    def align(pkt_idx: int) -> np.ndarray:
        sel = pidx == pkt_idx
        ids, vals = pfid[sel], pts[sel]
        out = np.full(fid.size, np.nan)
        pos = np.clip(np.searchsorted(fid, ids), 0, fid.size - 1)
        ok = fid[pos] == ids
        out[pos[ok]] = vals[ok]
        return out

    return align(1), {p: align(p) for p in PS}


def _day_rows(processed: pathlib.Path, day: str) -> list[dict]:
    flows = pq.read_table(
        processed / f"flows_{day}_labeled.parquet",
        columns=["flow_id", "t_last", "n_pkts_total", "label", "attack_type"],
    )
    pkts = pq.read_table(processed / f"packets_{day}.parquet", columns=["flow_id", "pkt_idx", "ts"])

    fid = flows.column("flow_id").to_numpy()
    t_last = flows.column("t_last").to_numpy().astype(np.float64)
    n_pk = flows.column("n_pkts_total").to_numpy()
    label = flows.column("label").to_numpy()
    atype = np.asarray(flows.column("attack_type").to_pylist(), dtype=object)
    # flow rows are NOT written in flow_id order; sort once so searchsorted can align the
    # packet table (which is sorted by (flow_id, pkt_idx)) against it.
    sort = np.argsort(fid, kind="stable")
    fid, t_last, n_pk, label, atype = fid[sort], t_last[sort], n_pk[sort], label[sort], atype[sort]

    pfid = pkts.column("flow_id").to_numpy()
    pidx = pkts.column("pkt_idx").to_numpy()
    pts = pkts.column("ts").to_numpy().astype(np.float64)
    order = np.lexsort((pidx, pfid))
    pfid, pidx, pts = pfid[order], pidx[order], pts[order]

    t1, tp = _per_flow_times(fid, pfid, pidx, pts)
    t1_ref = np.where(np.isnan(t1), t_last, t1)          # flows without packet 1 fall back to t_last

    groups: list[tuple[str, str, np.ndarray]] = [
        ("benign", "", label == 0),
        ("attack", "", label == 1),
    ]
    attack_types = sorted({str(a) for a, lab in zip(atype, label) if lab == 1 and str(a)})
    for name in attack_types:
        groups.append(("attack", name, (label == 1) & np.array([str(a) == name for a in atype])))

    rows: list[dict] = []
    for group, attack_type, gmask in groups:
        n_total = int(gmask.sum())
        if n_total == 0:
            continue
        for p in PS:
            has = ~np.isnan(tp[p]) & gmask
            n_with = int(has.sum())
            waits = tp[p][has] - t1_ref[has]
            delay = np.where(np.isnan(tp[p]), t_last - t1_ref, tp[p] - t1_ref)[gmask]
            rows.append(dict(
                day=day, group=group, attack_type=attack_type, p=p,
                n_flows_total=n_total, n_with_p=n_with,
                coverage=n_with / n_total,
                median_s=float(np.median(waits)) if waits.size else float("nan"),
                mean_s=float(waits.mean()) if waits.size else float("nan"),
                p95_s=_quantile(np.sort(waits), 0.95),
                max_s=float(waits.max()) if waits.size else float("nan"),
                median_delay_s=float(np.median(delay)) if delay.size else float("nan"),
                p95_delay_s=_quantile(np.sort(delay), 0.95),
            ))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--out", default="results/wait_p.csv")
    parser.add_argument("--days", nargs="+", default=list(DAYS), choices=list(DAYS))
    args = parser.parse_args(argv)

    processed = pathlib.Path(args.processed)
    rows: list[dict] = []
    for day in args.days:
        day_rows = _day_rows(processed, day)
        rows.extend(day_rows)
        print(f"{day}: {len(day_rows)} rows", flush=True)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in row.items()})
    print(f"\nwrote {len(rows)} rows to {out}")

    print("\npooled over days (median of per-day medians):")
    print(f"{'p':>2} {'group':>8} {'flows':>10} {'reach':>6} "
          f"{'wait_med':>9} {'delay_med':>10} {'delay_p95':>10}")
    for group in ("benign", "attack"):
        for p in PS:
            sel = [r for r in rows if r["group"] == group and r["attack_type"] == "" and r["p"] == p]
            flows = sum(r["n_flows_total"] for r in sel)
            reach = sum(r["n_with_p"] for r in sel) / max(1, flows)
            def med(key: str) -> float:
                vals = [r[key] for r in sel if not math.isnan(r[key])]
                return float(np.median(vals)) if vals else float("nan")
            print(f"{p:>2} {group:>8} {flows:>10d} {reach:>6.3f} "
                  f"{med('median_s'):>9.3f} {med('median_delay_s'):>10.3f} {med('p95_delay_s'):>10.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
