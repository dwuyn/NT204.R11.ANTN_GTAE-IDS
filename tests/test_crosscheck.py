"""Tests for the CICFlowMeter CSV cross-check (including the AM/PM bug)."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from src.label import ATTACK, BENIGN, UNCERTAIN, crosscheck_flows, load_csv_index

HEADER = [
    "Flow ID",
    " Source IP",
    " Source Port",
    " Destination IP",
    " Destination Port",
    " Protocol",
    " Timestamp",
    " Label",
]


def _ts(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> float:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp()


def _flow(flow_id, src, dst, ts, label, attack=None):
    return {
        "flow_id": flow_id,
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "t_first": ts,
        "label": label,
        "attack_type": attack,
    }


def _write_csv(path: Path, rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADER)
        for i, (src, dst, ts, label) in enumerate(rows):
            writer.writerow([i, src[0], src[1], dst[0], dst[1], 6, ts, label])


def test_crosscheck_matches_and_am_pm_shift(tmp_path):
    csv_path = tmp_path / "labels.csv"
    _write_csv(
        csv_path,
        [
            (("192.168.10.5", 50000), ("192.168.10.3", 53), "04/07/2017 09:25", "BENIGN"),
            (("205.174.165.73", 40000), ("192.168.10.50", 21), "04/07/2017 09:25", "FTP-Patator"),
            # Afternoon row stored 12 h early: 15:12 local -> 03:12 in the CSV.
            (("205.174.165.73", 40001), ("192.168.10.51", 444), "05/07/2017 03:12", "Heartbleed"),
            (("205.174.165.73", 40002), ("192.168.10.50", 80), "04/07/2017 12:00", "DoS Hulk"),
        ],
    )
    flows = [
        _flow(0, ("192.168.10.5", 50000), ("192.168.10.3", 53), _ts(2017, 7, 4, 9, 25), BENIGN),
        _flow(1, ("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 25), ATTACK, "FTP-Patator"),
        _flow(2, ("205.174.165.73", 40001), ("192.168.10.51", 444), _ts(2017, 7, 5, 15, 12), ATTACK, "Heartbleed"),
        _flow(3, ("10.9.9.9", 1234), ("10.9.9.8", 22), _ts(2017, 7, 4, 9, 25), BENIGN),
        _flow(4, ("205.174.165.73", 40002), ("192.168.10.50", 80), _ts(2017, 7, 4, 12, 0), BENIGN),
    ]
    index = load_csv_index(csv_path)
    report = crosscheck_flows(flows, index, utc_offset_minutes=0)

    assert report["flows"] == 5
    assert report["matched"] == 4
    assert report["unmatched"] == 1
    assert report["confusion"] == {"tn": 1, "fp": 0, "fn": 1, "tp": 2}
    assert report["agreement"] == 0.75
    assert len(report["mismatch_examples"]) == 1
    assert report["mismatch_examples"][0]["flow_id"] == 4


def test_uncertain_flows_are_skipped(tmp_path):
    csv_path = tmp_path / "labels.csv"
    _write_csv(
        csv_path,
        [(("192.168.10.5", 50000), ("192.168.10.3", 53), "04/07/2017 09:25", "BENIGN")],
    )
    flows = [
        _flow(0, ("192.168.10.5", 50000), ("192.168.10.3", 53), _ts(2017, 7, 4, 9, 25), UNCERTAIN),
    ]
    report = crosscheck_flows(flows, load_csv_index(csv_path), utc_offset_minutes=0)
    assert report["skipped_uncertain"] == 1
    assert report["matched"] == 0
    assert report["unmatched"] == 0


def test_tolerance_is_applied(tmp_path):
    csv_path = tmp_path / "labels.csv"
    _write_csv(
        csv_path,
        [(("192.168.10.5", 50000), ("192.168.10.3", 53), "04/07/2017 09:30", "BENIGN")],
    )
    flows = [
        _flow(0, ("192.168.10.5", 50000), ("192.168.10.3", 53), _ts(2017, 7, 4, 9, 25), BENIGN)
    ]
    index = load_csv_index(csv_path)
    assert crosscheck_flows(flows, index, 0, tolerance_s=120)["matched"] == 0
    assert crosscheck_flows(flows, index, 0, tolerance_s=400)["matched"] == 1


def test_csv_index_can_filter_keys(tmp_path):
    csv_path = tmp_path / "labels.csv"
    _write_csv(
        csv_path,
        [
            (("192.168.10.5", 50000), ("192.168.10.3", 53), "04/07/2017 09:25", "BENIGN"),
            (("205.174.165.73", 40000), ("192.168.10.50", 21), "04/07/2017 09:25", "FTP-Patator"),
        ],
    )
    key = (("192.168.10.50", 21), ("205.174.165.73", 40000))  # canonical (sorted) order
    index = load_csv_index(csv_path, keys={key})
    assert list(index) == [key]


def test_non_tcp_and_malformed_rows_are_skipped(tmp_path):
    csv_path = tmp_path / "mixed.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADER)
        # valid TCP row
        writer.writerow([0, "192.168.10.5", 50000, "192.168.10.3", 53, 6, "04/07/2017 09:25", "BENIGN"])
        # UDP row with empty ports (protocol 17)
        writer.writerow([1, "192.168.10.5", "", "192.168.10.3", "", 17, "04/07/2017 09:25", "BENIGN"])
        # malformed TCP row with an empty port
        writer.writerow([2, "192.168.10.5", "", "192.168.10.3", 53, 6, "04/07/2017 09:25", "BENIGN"])

    index = load_csv_index(csv_path)
    assert len(index) == 1
    assert next(iter(index)) == (("192.168.10.3", 53), ("192.168.10.5", 50000))
