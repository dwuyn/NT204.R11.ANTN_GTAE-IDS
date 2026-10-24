"""Tests for schedule-based labeling (synthetic flows; no pcap required)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path

import pytest

from src.label import (
    ATTACK,
    BENIGN,
    UNCERTAIN,
    AttackWindow,
    Schedule,
    classify_flow,
    label_flows,
    load_schedule,
    local_time,
    qa_summary,
)

SCHEDULE_PATH = Path(__file__).resolve().parents[1] / "configs" / "cicids2017_schedule.yaml"


@pytest.fixture(scope="module")
def schedule():
    return load_schedule(SCHEDULE_PATH)


def _ts(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> float:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp()


def _flow(
    src: tuple[str, int],
    dst: tuple[str, int],
    ts: float,
    start_with_syn: bool = True,
) -> dict:
    return {
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "t_first": ts,
        "start_with_syn": start_with_syn,
    }


def test_load_schedule_expands_ranges(schedule):
    assert len(schedule.windows) >= 18
    assert "205.174.165.73" in schedule.true_attackers
    ftp = [w for w in schedule.windows if w.attack == "FTP-Patator"]
    assert len(ftp) == 1
    assert (ftp[0].start.hour, ftp[0].start.minute) == (9, 20)
    assert ftp[0].ports == frozenset({21})


def test_ftp_attack_forward(schedule):
    flow = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 25))
    result = classify_flow(flow, schedule, utc_offset_minutes=0)
    assert result.label == ATTACK
    assert result.attack_type == "FTP-Patator"


def test_attack_reply_direction(schedule):
    flow = _flow(("192.168.10.50", 21), ("205.174.165.73", 40000), _ts(2017, 7, 4, 9, 25))
    assert classify_flow(flow, schedule, 0).label == ATTACK


def test_nat_alias_counts_inside_window(schedule):
    flow = _flow(("172.16.0.1", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 25))
    assert classify_flow(flow, schedule, 0).label == ATTACK


def test_nat_alias_outside_window_is_benign(schedule):
    flow = _flow(("172.16.0.1", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 11, 0))
    assert classify_flow(flow, schedule, 0).label == BENIGN


def test_wrong_service_port_is_uncertain(schedule):
    flow = _flow(("205.174.165.73", 40000), ("192.168.10.50", 80), _ts(2017, 7, 4, 9, 25))
    result = classify_flow(flow, schedule, 0)
    assert result.label == UNCERTAIN
    assert result.reason == "service_port_mismatch"


def test_attacker_outside_window_is_uncertain(schedule):
    flow = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 11, 0))
    result = classify_flow(flow, schedule, 0)
    assert result.label == UNCERTAIN
    assert result.reason == "known_attacker_outside_window"


def test_background_traffic_inside_window_is_benign(schedule):
    flow = _flow(("192.168.10.5", 50000), ("192.168.10.3", 53), _ts(2017, 7, 4, 9, 25))
    assert classify_flow(flow, schedule, 0).label == BENIGN


def test_padding_boundary(schedule):
    inside = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 19, 1))
    outside = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 18, 59))
    assert classify_flow(inside, schedule, 0).label == ATTACK
    assert classify_flow(outside, schedule, 0).label == UNCERTAIN


def test_timezone_offset_is_applied(schedule):
    flow = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 13, 25))
    assert classify_flow(flow, schedule, utc_offset_minutes=-240).label == ATTACK
    assert classify_flow(flow, schedule, utc_offset_minutes=0).label == UNCERTAIN


def test_offset_must_be_calibrated(schedule):
    flow = _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 25))
    with pytest.raises(ValueError):
        classify_flow(flow, schedule, utc_offset_minutes=None)


def test_flow_without_syn_is_uncertain(schedule):
    flow = _flow(
        ("205.174.165.73", 40000),
        ("192.168.10.50", 21),
        _ts(2017, 7, 4, 9, 25),
        start_with_syn=False,
    )
    result = classify_flow(flow, schedule, 0)
    assert result.label == UNCERTAIN
    assert result.reason == "flow_started_before_capture"


@pytest.mark.parametrize(
    "attack,src,dst,ts",
    [
        ("DoS Hulk", ("205.174.165.73", 40000), ("192.168.10.50", 80), _ts(2017, 7, 5, 10, 50)),
        ("Heartbleed", ("205.174.165.73", 40000), ("192.168.10.51", 444), _ts(2017, 7, 5, 15, 20)),
        ("Web Attack - Brute Force", ("205.174.165.73", 40000), ("192.168.10.50", 80), _ts(2017, 7, 6, 9, 30)),
        ("Bot", ("205.174.165.73", 40000), ("192.168.10.15", 8080), _ts(2017, 7, 7, 10, 30)),
        ("PortScan", ("205.174.165.73", 40000), ("192.168.10.50", 22), _ts(2017, 7, 7, 14, 0)),
        ("DDoS", ("205.174.165.69", 40000), ("192.168.10.50", 80), _ts(2017, 7, 7, 16, 0)),
    ],
)
def test_other_attack_windows(schedule, attack, src, dst, ts):
    result = classify_flow(_flow(src, dst, ts), schedule, 0)
    assert result.label == ATTACK
    assert result.attack_type == attack


def test_per_window_pad_overrides_global():
    window = AttackWindow(
        attack="PortScan",
        start=datetime(2017, 7, 7, 14, 0),
        end=datetime(2017, 7, 7, 14, 0, 10),
        attacker_ips=frozenset({"205.174.165.73"}),
        nat_aliases=frozenset(),
        victim_ips=frozenset({"192.168.10.50"}),
        victim_cidrs=(),
        ports=None,
    )
    flow = _flow(
        ("205.174.165.73", 40000), ("192.168.10.50", 22), _ts(2017, 7, 7, 13, 59, 30)
    )
    global_pad = Schedule(
        windows=(replace(window, pad_s=None),), true_attackers=frozenset()
    )
    zero_pad = Schedule(windows=(replace(window, pad_s=0),), true_attackers=frozenset())
    assert classify_flow(flow, global_pad, 0, pad_s=60).label == ATTACK
    assert classify_flow(flow, zero_pad, 0, pad_s=60).label == BENIGN


def test_cidr_victim_matching():
    window = AttackWindow(
        attack="Infiltration",
        start=datetime(2017, 7, 6, 15, 4),
        end=datetime(2017, 7, 6, 15, 45),
        attacker_ips=frozenset({"192.168.10.8"}),
        nat_aliases=frozenset(),
        victim_ips=frozenset(),
        victim_cidrs=(ip_network("192.168.10.0/24"),),
        ports=None,
    )
    schedule = Schedule(windows=(window,), true_attackers=frozenset())
    flow = _flow(("192.168.10.8", 50000), ("192.168.10.5", 445), _ts(2017, 7, 6, 15, 10))
    result = classify_flow(flow, schedule, 0)
    assert result.label == ATTACK
    assert result.attack_type == "Infiltration"


def test_benign_monday(schedule):
    flow = _flow(("192.168.10.5", 50000), ("192.168.10.50", 80), _ts(2017, 7, 3, 10, 0))
    assert classify_flow(flow, schedule, 0).label == BENIGN


def test_local_time_conversion():
    # 2017-07-04 13:25 UTC == 09:25 at UTC-4.
    assert local_time(_ts(2017, 7, 4, 13, 25), -240) == datetime(2017, 7, 4, 9, 25)


def test_label_flows_and_qa_summary(schedule):
    flows = [
        _flow(("205.174.165.73", 40000), ("192.168.10.50", 21), _ts(2017, 7, 4, 9, 25)),
        _flow(("192.168.10.5", 50000), ("192.168.10.3", 53), _ts(2017, 7, 4, 9, 25)),
        _flow(("205.174.165.73", 40000), ("192.168.10.50", 80), _ts(2017, 7, 4, 9, 25)),
    ]
    labeled = label_flows(flows, schedule, 0)
    assert [row["label"] for row in labeled] == [ATTACK, BENIGN, UNCERTAIN]
    summary = qa_summary(labeled)
    assert summary["total_flows"] == 3
    assert summary["attack_types"] == {"FTP-Patator": 1}
    assert summary["uncertain_rate"] == pytest.approx(1 / 3)
