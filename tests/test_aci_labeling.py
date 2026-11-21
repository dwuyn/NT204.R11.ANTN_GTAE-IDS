"""Tests for the ACI window labeller and the pcap merger (no network, no real captures)."""

from __future__ import annotations

import datetime as dt
import pathlib

import dpkt
import pytest

from scripts.label_aci import label_flows
from scripts.merge_pcaps import merge
from src.label import load_schedule

SCHEDULE = """
dataset: TEST
utc_offset_minutes: 0
windows:
  - date: "2023-11-01"
    attack: DoS-Slowloris
    ranges: [["09:58", "10:26"]]
    attacker_ips: []
    nat_aliases: []
    victim_ips: []
    ports: []
"""


def _flow(flow_id, t_first, sport=1000, start_with_syn=True):
    return {
        "flow_id": flow_id,
        "src_ip": "10.0.0.1",
        "src_port": sport,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "t_first": t_first,
        "t_last": t_first + 1.0,
        "n_pkts_total": 3,
        "start_with_syn": start_with_syn,
    }


def _epoch(h, m, s=0):
    return dt.datetime(2023, 11, 1, h, m, s, tzinfo=dt.timezone.utc).timestamp()


def test_window_membership_and_uncertain(tmp_path):
    schedule_path = tmp_path / "schedule.yaml"
    schedule_path.write_text(SCHEDULE, encoding="utf-8")
    schedule = load_schedule(schedule_path)

    flows = [
        _flow(0, _epoch(9, 30)),                    # before the window -> benign
        _flow(1, _epoch(10, 0)),                    # inside -> attack
        _flow(2, _epoch(10, 26)),                   # window end is inclusive -> attack
        _flow(3, _epoch(10, 30), sport=2000),       # after -> benign
        _flow(4, _epoch(9, 30), sport=3000, start_with_syn=False),  # -> UNCERTAIN
    ]
    labeled, summary = label_flows(flows, schedule, offset_minutes=0)
    by_id = {f["flow_id"]: f for f in labeled}
    assert by_id[0]["label"] == 0
    assert by_id[1]["label"] == 1 and by_id[1]["attack_type"] == "DoS-Slowloris"
    assert by_id[2]["label"] == 1
    assert by_id[3]["label"] == 0
    assert by_id[4]["label"] == -1
    assert summary["benign"] == 2 and summary["attack"] == 2 and summary["uncertain"] == 1


def test_duplicate_sniffer_copies_are_dropped(tmp_path):
    schedule_path = tmp_path / "schedule.yaml"
    schedule_path.write_text(SCHEDULE, encoding="utf-8")
    schedule = load_schedule(schedule_path)

    # same canonical 5-tuple captured by the wired and the wireless sniffer 30 ms apart
    flows = [
        _flow(0, 1000.000, sport=4444),
        _flow(1, 1000.030, sport=4444),
        _flow(2, 1005.000, sport=4444),   # a second connection, 5 s later -> kept
    ]
    labeled, summary = label_flows(flows, schedule, offset_minutes=0, dedup_window=0.5)
    assert len(labeled) == 2
    assert summary["duplicates_dropped"] == 1
    assert [f["flow_id"] for f in labeled] == [0, 2]


def _write_pcap(path: pathlib.Path, packets: list[bytes]) -> None:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh, snaplen=65535)
        for payload in packets:
            writer.writepkt(payload, ts=1.0)


def test_merge_strips_repeated_global_headers(tmp_path):
    from src.parse_pcap import _open_reader

    eth = dpkt.ethernet.Ethernet(
        dst=b"\x00\x11\x22\x33\x44\x55", src=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=dpkt.ip.IP(
            src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=6,
            data=dpkt.tcp.TCP(sport=1234, dport=80, flags=dpkt.tcp.TH_SYN),
        ),
    )
    first, second = tmp_path / "a.pcap", tmp_path / "b.pcap"
    _write_pcap(first, [bytes(eth)] * 3)
    _write_pcap(second, [bytes(eth)] * 2)
    out = tmp_path / "merged.pcap"
    files, size = merge([first, second], out)
    assert files == 2
    assert out.stat().st_size == first.stat().st_size + second.stat().st_size - 24
    with out.open("rb") as fh:
        count = sum(1 for _ in _open_reader(fh))
    assert count == 5
    assert size == out.stat().st_size


def test_merge_refuses_mismatched_headers(tmp_path):
    first = tmp_path / "a.pcap"
    second = tmp_path / "b.pcap"
    with first.open("wb") as fh:
        w = dpkt.pcap.Writer(fh, snaplen=65535)
        w.writepkt(b"x" * 40, ts=1.0)
    with second.open("wb") as fh:
        w = dpkt.pcap.Writer(fh, snaplen=1500)
        w.writepkt(b"y" * 40, ts=1.0)
    with pytest.raises(SystemExit):
        merge([first, second], tmp_path / "merged.pcap")


def test_label_table_matches_pure_python(tmp_path):
    import pyarrow as pa

    from scripts.label_aci import label_table

    schedule_path = tmp_path / "schedule.yaml"
    schedule_path.write_text(SCHEDULE, encoding="utf-8")
    schedule = load_schedule(schedule_path)

    rows = [
        _flow(0, _epoch(9, 30)),
        _flow(1, _epoch(10, 0)),
        _flow(2, 1000.000, sport=4444),
        _flow(3, 1000.030, sport=4444),      # duplicate capture of row 2
        _flow(4, _epoch(9, 30), sport=3000, start_with_syn=False),
    ]
    table = pa.Table.from_pylist(rows)
    labeled, summary = label_table(table, schedule, offset_minutes=0)
    assert labeled.num_rows == 4
    assert summary["duplicates_dropped"] == 1
    assert summary["attack"] == 1
    assert summary["uncertain"] == 1
    labels = dict(zip(labeled["flow_id"].to_pylist(), labeled["label"].to_pylist()))
    assert labels[1] == 1 and labels[0] == 0 and labels[4] == -1
    assert 3 not in labels
