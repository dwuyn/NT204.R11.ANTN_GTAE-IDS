"""Quantify F7: how many packets get a wrong label under the authors' row-shift bug.

Mechanism (``docs/REPRO_AUDIT.md`` §5.6): inside an attack window only packets between the
attacker and the victim enter ``dict_d_labels``; background packets in the same window have
no ``else`` branch and are silently skipped. The labels are then attached by *position*
(``pd.DataFrame(dict.values())`` assigned to the full frame, then ``dropna()``), so every
skipped packet shifts all following labels one row earlier, and the tail of the frame is
dropped.

This script replays that mechanism on our own correctly-labelled packets (one day) and
reports the label noise it would inject:

  * packets labelled attack that are truly background (false positives of the labelling),
  * true attack packets that lose their label,
  * flows touched by at least one mislabelled packet.

Assumption, stated explicitly: packets *outside* every attack window get their correct
benign label (the notebook labels benign traffic elsewhere); only the in-window background
packets are the ones skipped by the bug. This makes the estimate conservative.

    python scripts/eval_label_shift.py --day tuesday --offset-minutes -180
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import sys
from collections import Counter

import numpy as np
import pyarrow.parquet as pq

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.label import _pair_status, load_schedule, local_time  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", default="tuesday")
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--schedule", default="configs/cicids2017_schedule.yaml")
    parser.add_argument("--offset-minutes", type=int, default=-180)
    parser.add_argument("--out", default="results/label_shift_f7.csv")
    args = parser.parse_args(argv)

    schedule = load_schedule(args.schedule)
    flows = pq.read_table(
        pathlib.Path(args.processed) / f"flows_{args.day}_labeled.parquet",
        columns=["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "label", "attack_type"],
    ).to_pylist()
    flow_by_id = {int(f["flow_id"]): f for f in flows}
    packets = pq.read_table(
        pathlib.Path(args.processed) / f"packets_{args.day}.parquet", columns=["flow_id", "ts"]
    ).to_pylist()
    packets.sort(key=lambda p: (float(p["ts"]), int(p["flow_id"])))

    def correct_label(ts: float, flow: dict) -> tuple[str, bool]:
        """(label, skipped_by_bug) for one packet."""
        observed = local_time(ts, args.offset_minutes)
        for window in schedule.windows:
            inside = window.start <= observed <= window.end
            if not inside:
                continue
            status = _pair_status(
                {
                    "src_ip": flow["src_ip"], "src_port": flow["src_port"],
                    "dst_ip": flow["dst_ip"], "dst_port": flow["dst_port"],
                },
                window,
            )
            if status == "match":
                return window.attack, False
            return "Benign-in-window", True  # the notebook never labels this packet
        return "Benign", False

    labels: list[str] = []          # the buggy pipeline's label list (only labelled packets)
    full_true: list[str] = []       # true label of every packet, in stream order
    flow_of: list[int] = []
    skipped = 0
    for packet in packets:
        flow = flow_by_id[int(packet["flow_id"])]
        label, is_skipped = correct_label(float(packet["ts"]), flow)
        true_label = str(flow["attack_type"]) if int(flow["label"]) == 1 else "Benign"
        if is_skipped:
            skipped += 1
            full_true.append("Benign")          # background traffic in an attack window
            continue
        labels.append(true_label)               # what the notebook puts in the dict
        full_true.append(true_label)
        flow_of.append(int(packet["flow_id"]))

    n_total = len(packets)
    m_labels = len(labels)
    # positional assignment: row i receives labels[i] for i < M, the remaining rows are dropped
    bugged = [labels[i] if i < m_labels else None for i in range(n_total)]
    retained = m_labels
    mismatch = [i for i in range(retained) if bugged[i] != full_true[i]]
    attack_true = sum(1 for v in full_true[:retained] if v != "Benign")
    attack_pred = sum(1 for v in bugged[:retained] if v is not None and v != "Benign")
    tp = sum(1 for i in range(retained) if bugged[i] != "Benign" and full_true[i] == bugged[i])
    fp = sum(1 for i in range(retained) if bugged[i] != "Benign" and full_true[i] == "Benign")
    fn = sum(1 for i in range(retained) if bugged[i] == "Benign" and full_true[i] != "Benign")
    bad_flows = {flow_of[i] for i in mismatch}
    n = retained
    rows = [
        {"metric": "day", "value": args.day},
        {"metric": "packets_total", "value": n_total},
        {"metric": "packets_skipped_by_bug", "value": skipped},
        {"metric": "packets_retained_after_dropna", "value": n},
        {"metric": "packets_dropped", "value": n_total - retained},
        {"metric": "packets_mislabelled", "value": len(mismatch)},
        {"metric": "packet_mismatch_rate", "value": round(len(mismatch) / max(1, n), 6)},
        {"metric": "true_attack_packets", "value": attack_true},
        {"metric": "bugged_attack_labels", "value": attack_pred},
        {"metric": "attack_label_precision", "value": round(tp / max(1, attack_pred), 6)},
        {"metric": "attack_label_recall", "value": round(tp / max(1, attack_true), 6)},
        {"metric": "false_attack_labels", "value": fp},
        {"metric": "lost_attack_labels", "value": fn},
        {"metric": "flows_touched", "value": len(bad_flows)},
        {"metric": "flows_total", "value": len(flow_by_id)},
        {"metric": "touched_flow_rate", "value": round(len(bad_flows) / max(1, len(flow_by_id)), 6)},
    ]
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(f"{row['metric']:32s} {row['value']}")
    print(f"\nwrote {out}")
    print("label histogram (true):", dict(Counter(full_true[:retained]).most_common(5)))
    print("label histogram (bugged):", dict(Counter(v for v in bugged[:retained]).most_common(5)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
