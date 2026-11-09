"""Reproduce the authors' flow segmentation: assign pcap packets to CICFlowMeter
CSV flow rows (5-tuple + time window), take the first p packets per row.

This mirrors Payload-Byte / the official GTAE graph-generation notebooks.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import socket
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pyarrow.parquet as pq
import torch
from sklearn.preprocessing import StandardScaler
from pyod.models.hbos import HBOS
from pyod.models.iforest import IForest
from pyod.models.inne import INNE
from pyod.models.ocsvm import OCSVM

from src.packet_encoder import encode_edge, strip_headers
from src.parse_pcap import _open_reader


def load_flows(csv_path: str, label_filter: str | None) -> dict:
    rows_by_key: dict[tuple, list[dict]] = defaultdict(list)
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        cols = {name.strip(): i for i, name in enumerate(header)}
        max_i = max(cols.values())
        for row in reader:
            if len(row) <= max_i:
                continue
            if row[cols["Protocol"]].strip() != "6":
                continue
            label = row[cols["Label"]].strip()
            if label_filter is not None and label != label_filter:
                continue
            text = row[cols["Timestamp"]].strip()
            fmt = "%d/%m/%Y %H:%M:%S" if text.count(":") == 2 else "%d/%m/%Y %H:%M"
            dt = datetime.strptime(text, fmt).replace(
                tzinfo=timezone(timedelta(hours=-3))
            )
            if 1 <= dt.hour <= 7:  # CIC AM/PM bug: afternoon written as 1-7
                dt += timedelta(hours=12)
            start = dt.timestamp()
            duration = float(row[cols["Flow Duration"]]) / 1e6
            src, dst = row[cols["Source IP"]].strip(), row[cols["Destination IP"]].strip()
            sport, dport = int(row[cols["Source Port"]]), int(row[cols["Destination Port"]])
            key = (src, sport, dst, dport)
            rows_by_key[key].append(
                {
                    "start": start,
                    "end": start + 60.0 + duration,
                    "label": label,
                    "src": (src, sport),
                    "dst": (dst, dport),
                }
            )
    for rows in rows_by_key.values():
        rows.sort(key=lambda r: r["start"])
    return dict(rows_by_key)


def _match(rows: list[dict], starts: list[float], ts: float):
    idx = bisect.bisect_right(starts, ts + 60.0)
    for j in range(idx - 1, max(-1, idx - 40), -1):
        row = rows[j]
        if ts < row["start"] - 60.0:
            continue
        if ts <= row["end"]:
            return row
    return None


def collect(
    pcap_path: str,
    flows_by_key: dict,
    p: int,
    max_flows: int,
    start_utc: float | None = None,
    end_utc: float | None = None,
):
    starts = {k: [r["start"] for r in v] for k, v in flows_by_key.items()}
    selected: dict[int, list] = {}
    labels: dict[int, str] = {}
    for key, rows in flows_by_key.items():
        for i, row in enumerate(rows):
            row["id"] = (key, i)
    packet_count = 0
    with open(pcap_path, "rb") as fh:
        reader = _open_reader(fh)
        for ts, buf in reader:
            packet_count += 1
            if start_utc is not None and ts < start_utc:
                continue
            if end_utc is not None and ts > end_utc:
                break
            try:
                import dpkt

                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP) or ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                tcp = ip.data
                if not isinstance(tcp, dpkt.tcp.TCP):
                    continue
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                key = (src, tcp.sport, dst, tcp.dport)
                rev = (dst, tcp.dport, src, tcp.sport)
                row = None
                direction = 0
                if key in flows_by_key:
                    rows = flows_by_key[key]
                    row = _match(rows, starts[key], ts)
                if row is None and rev in flows_by_key:
                    rows = flows_by_key[rev]
                    row = _match(rows, starts[rev], ts)
                    direction = 1
                if row is None:
                    continue
                rid = row["id"]
                if rid not in selected:
                    selected[rid] = []
                    labels[rid] = row["label"]
                if len(selected[rid]) < p:
                    raw = bytes(ip)
                    ihl, thl = ip.hl * 4, tcp.off * 4
                    if thl < 20 or len(raw) < ihl + thl:
                        continue
                    selected[rid].append((strip_headers(raw[: ihl + thl]), direction))
                    if len(selected[rid]) == p and len(selected) >= max_flows:
                        print(f"collected {len(selected)} flows after {packet_count} packets", flush=True)
                        return selected, labels
            except Exception:
                continue
    print(f"collected {len(selected)} flows after {packet_count} packets", flush=True)
    return selected, labels


def features(selected: dict, labels: dict, p: int):
    X, y, names = [], [], []
    for rid, packets in selected.items():
        if len(packets) < p:
            continue
        X.append(encode_edge(packets, p))
        y.append(0 if labels[rid] == "BENIGN" else 1)
        names.append(labels[rid])
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int8), np.asarray(names)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--label", required=True, help="CIC label, e.g. BENIGN or DoS Hulk")
    parser.add_argument("--max-flows", type=int, default=5000)
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--start-utc", type=float, default=None)
    parser.add_argument("--end-utc", type=float, default=None)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    flows = load_flows(args.csv, args.label)
    print(f"CSV flows with label {args.label!r}: {sum(len(v) for v in flows.values())}", flush=True)
    selected, labels = collect(
        args.pcap, flows, args.p, args.max_flows, args.start_utc, args.end_utc
    )
    X, y, names = features(selected, labels, args.p)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out, X=X, y=y, names=names)
    print(f"saved {X.shape} to {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
