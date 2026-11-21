"""Label the merged ACI-IoT-2023 captures by attack *window* (no attacker IPs exist).

The ACI README publishes windows but not attacker addresses, so ``src/label.py`` (which
matches initiator/victim IP pairs) cannot be used. This script labels by time only:

  * a flow whose ``t_first`` falls inside a window of ``configs/aci_iot2023_schedule.yaml``
    becomes ATTACK with that window's class;
  * every other flow is BENIGN (the lab keeps generating benign background traffic on
    attack days, so "outside a window" is the only benign statement we can make);
  * a flow whose first packet is not SYN-without-ACK is UNCERTAIN (same policy as 2017).

Known bias, to be stated in every report: traffic that is benign but occurs *inside* an
attack window is labelled attack, because the README gives no attacker IPs.

Duplicate handling: each minute is captured twice (wired + wireless sniffer), so the same
TCP connection appears in both files with near-identical start times. Within a capture the
duplicates are removed by keeping the first of a run on the same canonical 5-tuple whose
start differs by at most ``--dedup-window`` seconds.

Memory: the merged captures are large (13 GiB => several million flows), so the labeling
path is vectorised over Arrow/NumPy columns. ``label_flows`` (pure Python) exists for tests
and small fixtures; it produces the same labels.

Usage::

    python scripts/label_aci.py            # writes flows_aci_*_labeled.parquet in place
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from collections import Counter

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.label import load_schedule, local_time  # noqa: E402

TAGS = ("aci_benign1", "aci_benign2", "aci_recon", "aci_brute", "aci_slowloris")


# --------------------------------------------------------------------------- pure python
def _canonical_key(flow: dict) -> tuple:
    a = (str(flow["src_ip"]), int(flow["src_port"]))
    b = (str(flow["dst_ip"]), int(flow["dst_port"]))
    return (a, b) if a <= b else (b, a)


def label_flows(
    flows: list[dict],
    schedule,
    offset_minutes: int,
    dedup_window: float = 0.5,
) -> tuple[list[dict], dict]:
    """Small-fixture implementation; mirrors :func:`label_table` exactly."""
    ordered = sorted(flows, key=lambda f: (_canonical_key(f), float(f["t_first"])))
    kept: list[dict] = []
    last_by_key: dict[tuple, float] = {}
    dropped = 0
    for flow in ordered:
        key = _canonical_key(flow)
        t_first = float(flow["t_first"])
        previous = last_by_key.get(key)
        if previous is not None and t_first - previous <= dedup_window:
            dropped += 1
            continue
        last_by_key[key] = t_first
        kept.append(flow)

    reasons: Counter = Counter()
    attack_types: Counter = Counter()
    for flow in kept:
        if flow.get("start_with_syn") is False:
            flow.update(label=-1, attack_type=None, label_reason="flow_started_before_capture")
            reasons["flow_started_before_capture"] += 1
            continue
        observed = local_time(float(flow["t_first"]), offset_minutes)
        match = next((w for w in schedule.windows if w.start <= observed <= w.end), None)
        if match is not None:
            flow.update(label=1, attack_type=match.attack, label_reason=f"window:{match.attack}")
            attack_types[match.attack] += 1
            reasons[flow["label_reason"]] += 1
        else:
            flow.update(label=0, attack_type=None, label_reason="outside_window")
            reasons["outside_window"] += 1
    summary = _summary(len(flows), len(kept), dropped, kept)
    return kept, summary


def _summary(read: int, kept: int, dropped: int, rows) -> dict:
    labels = [int(r["label"]) for r in rows]
    attacks = Counter(str(r["attack_type"]) for r in rows if int(r["label"]) == 1)
    reasons = Counter(str(r["label_reason"]) for r in rows)
    return {
        "flows_read": read,
        "flows_kept": kept,
        "duplicates_dropped": dropped,
        "benign": sum(1 for v in labels if v == 0),
        "attack": sum(1 for v in labels if v == 1),
        "uncertain": sum(1 for v in labels if v == -1),
        "attack_types": dict(sorted(attacks.items())),
        "label_reasons": dict(sorted(reasons.items())),
    }


# ------------------------------------------------------------------------- vectorised
def _utc_window(window, offset_minutes: int) -> tuple[float, float]:
    """Schedule window (local naive) expressed in pcap epoch seconds."""
    delta = dt.timedelta(minutes=offset_minutes)
    start = (window.start - delta).replace(tzinfo=dt.timezone.utc).timestamp()
    end = (window.end - delta).replace(tzinfo=dt.timezone.utc).timestamp()
    return start, end


def label_table(
    table: pa.Table,
    schedule,
    offset_minutes: int,
    dedup_window: float = 0.5,
) -> tuple[pa.Table, dict]:
    n = table.num_rows
    t_first = table.column("t_first").to_numpy().astype(np.float64)
    if "start_with_syn" in table.column_names:
        syn_ok = table.column("start_with_syn").to_numpy().astype(bool)
    else:
        syn_ok = np.ones(n, dtype=bool)

    labels = np.zeros(n, dtype=np.int8)
    attack_type = np.full(n, None, dtype=object)
    reason = np.full(n, "outside_window", dtype=object)
    for window in schedule.windows:
        start, end = _utc_window(window, offset_minutes)
        mask = (t_first >= start) & (t_first <= end) & (labels == 0)
        labels[mask] = 1
        attack_type[mask] = window.attack
        reason[mask] = f"window:{window.attack}"
    labels[~syn_ok] = -1
    attack_type[~syn_ok] = None
    reason[~syn_ok] = "flow_started_before_capture"

    keep = _dedup_mask(table, t_first, dedup_window)
    dropped = int(n - keep.sum())

    out = table.filter(pa.array(keep))
    out = out.append_column("label", pa.array(labels[keep], type=pa.int8()))
    out = out.append_column("attack_type", pa.array(attack_type[keep].tolist(), type=pa.string()))
    out = out.append_column("label_reason", pa.array(reason[keep].tolist(), type=pa.string()))

    summary = {
        "flows_read": int(n),
        "flows_kept": int(keep.sum()),
        "duplicates_dropped": dropped,
        "benign": int(((labels == 0) & keep).sum()),
        "attack": int(((labels == 1) & keep).sum()),
        "uncertain": int(((labels == -1) & keep).sum()),
        "attack_types": {
            str(k): int(((attack_type == k) & keep).sum())
            for k in {a for a in attack_type if a}
        },
        "label_reasons": {
            str(k): int(((reason == k) & keep).sum()) for k in {r for r in reason}
        },
    }
    return out, summary


def _dedup_mask(table: pa.Table, t_first: np.ndarray, dedup_window: float) -> np.ndarray:
    """True for kept rows; drops the second of two copies of the same connection.

    Sorted by (canonical 5-tuple, t_first), a duplicate is a row whose 5-tuple equals the
    previous row's and whose start is within ``dedup_window`` seconds. Chained copies are
    all dropped because the comparison is between consecutive sorted rows.
    """
    src = pc.binary_join_element_wise(
        table.column("src_ip").cast(pa.string()), table.column("src_port").cast(pa.string()), ":"
    )
    dst = pc.binary_join_element_wise(
        table.column("dst_ip").cast(pa.string()), table.column("dst_port").cast(pa.string()), ":"
    )
    low = pc.min_element_wise(src, dst)
    high = pc.max_element_wise(src, dst)
    key = pc.binary_join_element_wise(low, high, "|")
    if isinstance(key, pa.ChunkedArray):
        key = key.combine_chunks()          # one dictionary for all rows, not per chunk
    codes = pc.dictionary_encode(key).indices.to_numpy(zero_copy_only=False)
    order = np.lexsort((t_first, codes))
    sorted_codes = codes[order]
    sorted_t = t_first[order]
    duplicate = np.zeros(order.size, dtype=bool)
    if order.size > 1:
        same_key = sorted_codes[1:] == sorted_codes[:-1]
        close = (sorted_t[1:] - sorted_t[:-1]) <= dedup_window
        duplicate[1:] = same_key & close
    keep_sorted = ~duplicate
    keep = np.empty(order.size, dtype=bool)
    keep[order] = keep_sorted
    return keep


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed/aci")
    parser.add_argument("--schedule", default="configs/aci_iot2023_schedule.yaml")
    parser.add_argument("--tags", nargs="+", default=list(TAGS))
    parser.add_argument("--dedup-window", type=float, default=0.5)
    parser.add_argument("--qa-dir", default="reports")
    args = parser.parse_args(argv)

    schedule = load_schedule(args.schedule)
    raw = yaml.safe_load(pathlib.Path(args.schedule).read_text(encoding="utf-8"))
    offset = raw.get("utc_offset_minutes")
    if offset is None:
        raise SystemExit("utc_offset_minutes is not calibrated in the schedule")

    processed = pathlib.Path(args.processed)
    qa_dir = pathlib.Path(args.qa_dir)
    qa_dir.mkdir(parents=True, exist_ok=True)
    totals = Counter()
    for tag in args.tags:
        path = processed / f"flows_{tag}.parquet"
        if not path.exists():
            raise FileNotFoundError(path)
        table = pq.read_table(path)
        labeled, summary = label_table(table, schedule, int(offset), args.dedup_window)
        out = processed / f"flows_{tag}_labeled.parquet"
        pq.write_table(labeled, out)
        (qa_dir / f"qa_labeling_{tag}.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        for key in ("flows_read", "flows_kept", "duplicates_dropped", "benign", "attack", "uncertain"):
            totals[key] += int(summary[key])
        print(f"{tag}: kept={summary['flows_kept']:8d} benign={summary['benign']:8d} "
              f"attack={summary['attack']:8d} uncertain={summary['uncertain']:6d} "
              f"dupes={summary['duplicates_dropped']:7d} {summary['attack_types']}", flush=True)
        del table, labeled
    print(f"total: {dict(totals)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
