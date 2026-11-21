"""Tests for the wait_p measurement (wait for p packets vs wait for flow close)."""

from __future__ import annotations

import pyarrow as pa
import pyarrow.parquet as pq

from scripts.eval_wait_p import _day_rows

FLOW_SCHEMA = pa.schema([
    ("flow_id", pa.int64()),
    ("t_last", pa.float64()),
    ("n_pkts_total", pa.int64()),
    ("label", pa.int8()),
    ("attack_type", pa.string()),
])
PACKET_SCHEMA = pa.schema([
    ("flow_id", pa.int64()),
    ("pkt_idx", pa.int64()),
    ("ts", pa.float64()),
])


def _write(processed, day, flows, packets):
    pq.write_table(pa.Table.from_pylist(flows, schema=FLOW_SCHEMA), processed / f"flows_{day}_labeled.parquet")
    pq.write_table(pa.Table.from_pylist(packets, schema=PACKET_SCHEMA), processed / f"packets_{day}.parquet")


def test_wait_and_delay_columns(tmp_path):
    processed = tmp_path
    flows = [
        {"flow_id": 1, "t_last": 0.2, "n_pkts_total": 3, "label": 0, "attack_type": None},
        {"flow_id": 2, "t_last": 5.0, "n_pkts_total": 1, "label": 0, "attack_type": None},
        {"flow_id": 3, "t_last": 2.5, "n_pkts_total": 2, "label": 1, "attack_type": "PortScan"},
    ]
    packets = [
        {"flow_id": 1, "pkt_idx": 1, "ts": 0.0},
        {"flow_id": 1, "pkt_idx": 2, "ts": 0.1},
        {"flow_id": 1, "pkt_idx": 3, "ts": 0.2},
        {"flow_id": 2, "pkt_idx": 1, "ts": 1.0},
        {"flow_id": 3, "pkt_idx": 1, "ts": 2.0},
        {"flow_id": 3, "pkt_idx": 2, "ts": 2.5},
    ]
    _write(processed, "t", flows, packets)

    rows = _day_rows(processed, "t")
    p2 = {(r["group"], r["attack_type"]): r for r in rows if r["p"] == 2}

    benign = p2[("benign", "")]
    # only flow 1 has a 2nd packet -> wait = 0.1; delay includes flow 2 (close at 5.0)
    assert benign["n_flows_total"] == 2
    assert benign["n_with_p"] == 1
    assert abs(benign["median_s"] - 0.1) < 1e-9
    assert abs(benign["median_delay_s"] - (0.1 + 4.0) / 2) < 1e-9

    attack = p2[("attack", "")]
    assert attack["n_flows_total"] == 1 and attack["n_with_p"] == 1
    assert abs(attack["median_s"] - 0.5) < 1e-9
    assert abs(attack["median_delay_s"] - 0.5) < 1e-9

    per_class = p2[("attack", "PortScan")]
    assert per_class["n_flows_total"] == 1

    # p=3: flow 1 has a third packet (wait 0.2), flow 2 still falls back to t_last
    p3 = {(r["group"], r["attack_type"]): r for r in rows if r["p"] == 3}
    assert abs(p3[("benign", "")]["median_delay_s"] - (0.2 + 4.0) / 2) < 1e-9
    assert abs(p3[("benign", "")]["median_s"] - 0.2) < 1e-9
