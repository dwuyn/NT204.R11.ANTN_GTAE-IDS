"""Tests for the streaming pcap parser (synthetic pcaps, no dataset needed)."""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt
import pyarrow.parquet as pq
import pytest

from src.packet_encoder import KEPT_BYTES
from src.parse_pcap import parse_pcap

CLIENT = ("192.168.10.5", 50000)
SERVER = ("192.168.10.50", 80)


def _pkt(
    src: tuple[str, int],
    dst: tuple[str, int],
    flags: int,
    seq: int = 1,
    proto: int = dpkt.ip.IP_PROTO_TCP,
) -> bytes:
    if proto == dpkt.ip.IP_PROTO_TCP:
        l4 = dpkt.tcp.TCP(
            sport=src[1], dport=dst[1], seq=seq, flags=flags, win=8192, off=5
        )
    else:
        l4 = dpkt.udp.UDP(sport=src[1], dport=dst[1], data=b"x")
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src[0]),
        dst=socket.inet_aton(dst[0]),
        p=proto,
        ttl=64,
        id=1,
        data=l4,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01",
        dst=b"\x00\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)
        writer.close()


def _write_pcapng(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with open(path, "wb") as fh:
        writer = dpkt.pcapng.Writer(fh)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)
        writer.close()


def _read(path: Path) -> list[dict]:
    return pq.read_table(path).to_pylist()


def test_basic_flow_direction_and_drops(tmp_path):
    pcap = tmp_path / "basic.pcap"
    _write_pcap(
        pcap,
        [
            (0.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)),
            (0.1, _pkt(SERVER, CLIENT, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=100)),
            (0.2, _pkt(CLIENT, SERVER, dpkt.tcp.TH_ACK, seq=2, )),
            (0.3, _pkt(CLIENT, SERVER, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, seq=2)),
            (1.0, _pkt(CLIENT, SERVER, 0, proto=dpkt.ip.IP_PROTO_UDP)),
            (2.0, _pkt(("10.0.0.9", 1234), ("10.0.0.8", 22), dpkt.tcp.TH_ACK)),
        ],
    )
    summary = parse_pcap(pcap, tmp_path / "out", "test")

    assert summary["packets_written"] == 5
    assert summary["flows_written"] == 2
    assert summary["counters"]["proto_17_dropped"] == 1

    flows = _read(tmp_path / "out" / "flows_test.parquet")
    packets = _read(tmp_path / "out" / "packets_test.parquet")
    assert [f["start_with_syn"] for f in flows] == [True, False]
    assert flows[0]["src_ip"] == CLIENT[0] and flows[0]["src_port"] == CLIENT[1]
    assert flows[0]["n_pkts_total"] == 4
    assert flows[1]["n_pkts_total"] == 1
    assert [p["dir"] for p in packets[:4]] == [0, 1, 0, 0]
    assert [p["pkt_idx"] for p in packets[:4]] == [1, 2, 3, 4]
    assert all(len(p["kept25"]) == KEPT_BYTES for p in packets)


def test_only_first_eight_packets_stored(tmp_path):
    pcap = tmp_path / "many.pcap"
    packets = [(i * 0.01, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN if i == 0 else dpkt.tcp.TH_ACK)) for i in range(12)]
    _write_pcap(pcap, packets)

    summary = parse_pcap(pcap, tmp_path / "out", "many")
    rows = _read(tmp_path / "out" / "packets_many.parquet")
    flows = _read(tmp_path / "out" / "flows_many.parquet")
    assert summary["packets_written"] == 8
    assert len(rows) == 8
    assert flows[0]["n_pkts_total"] == 12


def test_idle_timeout_splits_flow(tmp_path):
    pcap = tmp_path / "idle.pcap"
    _write_pcap(
        pcap,
        [
            (0.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)),
            (130.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_ACK)),
        ],
    )
    summary = parse_pcap(pcap, tmp_path / "out", "idle", idle_timeout=120.0)
    flows = _read(tmp_path / "out" / "flows_idle.parquet")
    assert summary["flows_written"] == 2
    assert flows[1]["start_with_syn"] is False


def test_fin_does_not_split_teardown_ack(tmp_path):
    pcap = tmp_path / "fin.pcap"
    _write_pcap(
        pcap,
        [
            (0.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)),
            (0.1, _pkt(CLIENT, SERVER, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)),
            (0.2, _pkt(SERVER, CLIENT, dpkt.tcp.TH_ACK)),
            (0.3, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN, seq=9)),
        ],
    )
    summary = parse_pcap(pcap, tmp_path / "out", "fin")
    flows = _read(tmp_path / "out" / "flows_fin.parquet")
    assert summary["flows_written"] == 2
    assert [f["n_pkts_total"] for f in flows] == [3, 1]
    assert summary["counters"]["flows_reopened"] == 1


def test_rst_does_not_split_flow(tmp_path):
    pcap = tmp_path / "rst.pcap"
    _write_pcap(
        pcap,
        [
            (0.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)),
            (0.1, _pkt(CLIENT, SERVER, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)),
            (0.2, _pkt(SERVER, CLIENT, dpkt.tcp.TH_ACK)),
            (0.3, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN, seq=9)),
        ],
    )
    summary = parse_pcap(pcap, tmp_path / "out", "rst")
    flows = _read(tmp_path / "out" / "flows_rst.parquet")
    assert summary["flows_written"] == 2
    assert [f["n_pkts_total"] for f in flows] == [3, 1]
    assert flows[1]["start_with_syn"] is True
    assert summary["counters"]["flows_with_rst"] == 1


def test_pcapng_input(tmp_path):
    pcapng = tmp_path / "input.pcapng"
    _write_pcapng(
        pcapng,
        [
            (0.0, _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)),
            (0.1, _pkt(SERVER, CLIENT, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=100)),
        ],
    )
    summary = parse_pcap(pcapng, tmp_path / "out", "ng")
    assert summary["packets_written"] == 2
    assert summary["flows_written"] == 1


def test_max_packets_limits_input(tmp_path):
    pcap = tmp_path / "limit.pcap"
    _write_pcap(
        pcap,
        [(float(i), _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN if i == 0 else dpkt.tcp.TH_ACK)) for i in range(20)],
    )
    summary = parse_pcap(pcap, tmp_path / "out", "limit", max_packets=5)
    assert summary["counters"]["packets_read"] == 5


def test_truncated_header_is_counted(tmp_path):
    pcap = tmp_path / "trunc.pcap"
    pkt = _pkt(CLIENT, SERVER, dpkt.tcp.TH_SYN)
    _write_pcap(pcap, [(0.0, pkt[:38])])  # cut inside the TCP header
    summary = parse_pcap(pcap, tmp_path / "out", "trunc")
    assert summary["packets_written"] == 0
    dropped = summary["counters"].get("truncated_header", 0) + summary["counters"].get(
        "malformed_tcp", 0
    )
    assert dropped == 1
