"""Flow labeling from the CIC-IDS2017 attack schedule (design doc §4.3).

A pcap carries no labels. Each flow is labeled by combining:

1. the CIC attack schedule (date, local time window, attacker/victim IPs, NAT);
2. a cross-check against the published CICFlowMeter CSV (done by the caller).

Rules implemented here:

* ATTACK (1)  : the flow's local start time is inside a window (± pad) and one
  endpoint is an attacker (or a NAT alias active in that window) while the
  other endpoint is that window's victim; if the window declares service
  ports, one of the two ports must match.
* UNCERTAIN (-1): the pair matches but the service port does not, or the flow
  involves a known attacker inside a window without matching a victim, or a
  known attacker appears outside any window.
* BENIGN (0)  : everything else, including background traffic during an
  attack window.

Labels are only used for evaluation and for selecting benign training flows;
the GTAE and the detectors never see attack labels.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable, Mapping

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

BENIGN = 0
ATTACK = 1
UNCERTAIN = -1


@dataclass(frozen=True)
class AttackWindow:
    attack: str
    start: datetime
    end: datetime
    attacker_ips: frozenset[str]
    nat_aliases: frozenset[str]
    victim_ips: frozenset[str]
    victim_cidrs: tuple[IPv4Network, ...]
    ports: frozenset[int] | None
    variant: str | None = None
    pad_s: int | None = None

    @property
    def initiator_ips(self) -> frozenset[str]:
        return self.attacker_ips | self.nat_aliases


@dataclass(frozen=True)
class Schedule:
    windows: tuple[AttackWindow, ...]
    true_attackers: frozenset[str]


@dataclass(frozen=True)
class Label:
    label: int
    attack_type: str | None
    reason: str


def load_schedule(path: str | Path) -> Schedule:
    """Load and validate the YAML schedule; ranges are expanded into windows."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    windows: list[AttackWindow] = []
    for item in raw["windows"]:
        date = item["date"]
        for start_s, end_s in item["ranges"]:
            start = datetime.fromisoformat(f"{date}T{start_s}")
            end = datetime.fromisoformat(f"{date}T{end_s}")
            if end < start:
                raise ValueError(f"inverted window {date} {start_s}-{end_s}")
            if end == start:
                # CIC prints some one-minute bursts as "14:33 - 14:33".
                end = start + timedelta(seconds=59)
            windows.append(
                AttackWindow(
                    attack=item["attack"],
                    variant=item.get("variant"),
                    start=start,
                    end=end,
                    attacker_ips=frozenset(item.get("attacker_ips", [])),
                    nat_aliases=frozenset(item.get("nat_aliases", [])),
                    victim_ips=frozenset(item.get("victim_ips", [])),
                    victim_cidrs=tuple(
                        ip_network(cidr, strict=False) for cidr in item.get("victim_cidrs", [])
                    ),
                    ports=frozenset(item["ports"]) if item.get("ports") else None,
                    pad_s=item.get("pad_s"),
                )
            )
    windows.sort(key=lambda w: w.start)
    return Schedule(
        windows=tuple(windows),
        true_attackers=frozenset(raw.get("true_attackers", [])),
    )


def local_time(t_utc: float, utc_offset_minutes: int) -> datetime:
    """Convert a pcap epoch timestamp to the schedule's naive local time."""
    utc = datetime.fromtimestamp(float(t_utc), tz=timezone.utc).replace(tzinfo=None)
    return utc + timedelta(minutes=utc_offset_minutes)


def _is_victim(ip: str, window: AttackWindow) -> bool:
    if ip in window.victim_ips:
        return True
    if not window.victim_cidrs:
        return False
    addr = ip_address(ip)
    return any(addr in net for net in window.victim_cidrs)


def _pair_status(flow: Mapping[str, Any], window: AttackWindow) -> str | None:
    """Return 'match', 'port_mismatch' or None for either flow direction."""
    ends = (
        (str(flow["src_ip"]), int(flow["src_port"])),
        (str(flow["dst_ip"]), int(flow["dst_port"])),
    )
    for i in (0, 1):
        initiator_ip, initiator_port = ends[i]
        victim_ip, victim_port = ends[1 - i]
        if initiator_ip in window.initiator_ips and _is_victim(victim_ip, window):
            if window.ports is None:
                return "match"
            if initiator_port in window.ports or victim_port in window.ports:
                return "match"
            return "port_mismatch"
    return None


def classify_flow(
    flow: Mapping[str, Any],
    schedule: Schedule,
    utc_offset_minutes: int,
    pad_s: int = 60,
) -> Label:
    """Label one flow; raises if the timezone offset has not been calibrated."""
    if utc_offset_minutes is None:
        raise ValueError("utc_offset_minutes is not calibrated (T6)")
    if flow.get("start_with_syn") is False:
        return Label(UNCERTAIN, None, "flow_started_before_capture")

    observed = local_time(flow["t_first"], utc_offset_minutes)
    ends_ips = {str(flow["src_ip"]), str(flow["dst_ip"])}

    saw_true_attacker = False
    for window in schedule.windows:
        window_pad = timedelta(seconds=window.pad_s if window.pad_s is not None else pad_s)
        if observed < window.start - window_pad or observed > window.end + window_pad:
            continue
        status = _pair_status(flow, window)
        if status == "match":
            return Label(ATTACK, window.attack, f"window:{window.attack}")
        if status == "port_mismatch":
            return Label(UNCERTAIN, window.attack, "service_port_mismatch")
        if ends_ips & window.attacker_ips:
            saw_true_attacker = True

    if saw_true_attacker:
        return Label(UNCERTAIN, None, "attacker_in_window_no_victim_match")
    if ends_ips & schedule.true_attackers:
        return Label(UNCERTAIN, None, "known_attacker_outside_window")
    return Label(BENIGN, None, "no_attack_window")


def label_flows(
    flows: Iterable[Mapping[str, Any]],
    schedule: Schedule,
    utc_offset_minutes: int,
    pad_s: int = 60,
) -> list[dict[str, Any]]:
    """Return shallow copies of the flows with label/attack_type/label_reason."""
    labeled = []
    for flow in flows:
        result = classify_flow(flow, schedule, utc_offset_minutes, pad_s)
        labeled.append(
            {
                **flow,
                "label": result.label,
                "attack_type": result.attack_type,
                "label_reason": result.reason,
            }
        )
    return labeled


def qa_summary(labeled: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate label QC counters for reports/qa_labeling.md."""
    rows = list(labeled)
    counts = Counter(int(r["label"]) for r in rows)
    attack_types = Counter(
        str(r["attack_type"]) for r in rows if int(r["label"]) == ATTACK
    )
    reasons = Counter(str(r["label_reason"]) for r in rows)
    total = len(rows)
    uncertain = counts[UNCERTAIN]
    return {
        "total_flows": total,
        "benign": counts[BENIGN],
        "attack": counts[ATTACK],
        "uncertain": uncertain,
        "uncertain_rate": (uncertain / total) if total else 0.0,
        "attack_types": dict(sorted(attack_types.items())),
        "label_reasons": dict(sorted(reasons.items())),
    }


def _canonical_key(
    src_ip: Any, src_port: Any, dst_ip: Any, dst_port: Any
) -> tuple[tuple[str, int], tuple[str, int]]:
    a = (str(src_ip), int(src_port))
    b = (str(dst_ip), int(dst_port))
    return (a, b) if a <= b else (b, a)


def _parse_csv_timestamp(raw: str) -> datetime:
    text = raw.strip()
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"unrecognized CIC timestamp: {raw!r}")


def csv_binary_label(raw: str) -> int:
    return BENIGN if raw.strip().upper() == "BENIGN" else ATTACK


def load_csv_index(
    path: str | Path, keys: set[tuple] | None = None
) -> dict[tuple, list[tuple[datetime, str]]]:
    """Index GeneratedLabelledFlows rows by canonical 5-tuple.

    ``keys`` limits memory when only a subset of flows is being cross-checked.
    """
    index: dict[tuple, list[tuple[datetime, str]]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        cols = {name.strip(): i for i, name in enumerate(header)}
        required = [
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Timestamp",
            "Label",
        ]
        missing = [name for name in required if name not in cols]
        if missing:
            raise ValueError(f"CSV is missing columns: {missing}")
        protocol_i = cols.get("Protocol")
        max_i = max(cols[name] for name in required)
        for row in reader:
            if not row or len(row) <= max_i:
                continue
            # Edge features are defined on TCP/IPv4 only; non-TCP rows also
            # carry empty ports, so drop them before parsing the tuple.
            if protocol_i is not None and row[protocol_i].strip() != "6":
                continue
            try:
                key = _canonical_key(
                    row[cols["Source IP"]],
                    row[cols["Source Port"]],
                    row[cols["Destination IP"]],
                    row[cols["Destination Port"]],
                )
                timestamp = _parse_csv_timestamp(row[cols["Timestamp"]])
            except (ValueError, IndexError):
                continue
            if keys is not None and key not in keys:
                continue
            index[key].append((timestamp, row[cols["Label"]]))
    return dict(index)


def crosscheck_flows(
    labeled: Iterable[Mapping[str, Any]],
    csv_index: Mapping[tuple, list[tuple[datetime, str]]],
    utc_offset_minutes: int,
    tolerance_s: float = 120.0,
) -> dict[str, Any]:
    """Compare our labels with the CICFlowMeter CSV.

    CIC CSV timestamps have a known AM/PM bug (afternoon rows stored 12 h
    earlier), so each candidate is tried at t, t+12h and t-12h. CSV timestamps
    have minute resolution, hence the default 120 s tolerance.
    """
    rows = list(labeled)
    decided = [flow for flow in rows if int(flow["label"]) != UNCERTAIN]
    confusion: Counter[tuple[int, int]] = Counter()
    matched = 0
    examples: list[dict[str, Any]] = []
    shifts = (timedelta(0), timedelta(hours=12), timedelta(hours=-12))

    for flow in decided:
        key = _canonical_key(
            flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"]
        )
        candidates = csv_index.get(key)
        if not candidates:
            continue
        target = local_time(flow["t_first"], utc_offset_minutes)
        best: tuple[float, datetime, str] | None = None
        for csv_ts, csv_label in candidates:
            for shift in shifts:
                delta = abs((csv_ts + shift - target).total_seconds())
                if delta <= tolerance_s and (best is None or delta < best[0]):
                    best = (delta, csv_ts + shift, csv_label)
        if best is None:
            continue
        matched += 1
        ours = int(flow["label"])
        theirs = csv_binary_label(best[2])
        confusion[(ours, theirs)] += 1
        if ours != theirs and len(examples) < 10:
            examples.append(
                {
                    "flow_id": int(flow["flow_id"]),
                    "ours": ours,
                    "csv_label": best[2],
                    "delta_s": round(best[0], 1),
                }
            )

    total = len(rows)
    decided_total = len(decided)
    return {
        "flows": total,
        "skipped_uncertain": total - decided_total,
        "matched": matched,
        "unmatched": decided_total - matched,
        "match_rate": (matched / decided_total) if decided_total else 0.0,
        "agreement": (
            (confusion[(BENIGN, BENIGN)] + confusion[(ATTACK, ATTACK)]) / matched
            if matched
            else 0.0
        ),
        "confusion": {
            "tn": confusion[(BENIGN, BENIGN)],
            "fp": confusion[(ATTACK, BENIGN)],
            "fn": confusion[(BENIGN, ATTACK)],
            "tp": confusion[(ATTACK, ATTACK)],
        },
        "mismatch_examples": examples,
    }



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", required=True, help="flows_{day}.parquet from parse_pcap")
    parser.add_argument(
        "--schedule", default="configs/cicids2017_schedule.yaml", help="attack schedule YAML"
    )
    parser.add_argument(
        "--offset-minutes",
        type=int,
        required=True,
        help="UTC -> CIC local time, calibrated in T6 (e.g. -240)",
    )
    parser.add_argument("--pad-s", type=int, default=60)
    parser.add_argument("--out", required=True, help="output labeled flows parquet")
    parser.add_argument("--qa", default=None, help="optional QA summary JSON path")
    parser.add_argument(
        "--csv",
        action="append",
        default=None,
        help="GeneratedLabelledFlows CSV; repeat for days split into several CSVs",
    )
    parser.add_argument(
        "--crosscheck", default=None, help="optional cross-check report JSON path"
    )
    parser.add_argument(
        "--tolerance-s",
        type=float,
        default=120.0,
        help="CSV join tolerance; CSV timestamps have minute resolution",
    )
    args = parser.parse_args(argv)

    schedule = load_schedule(args.schedule)
    rows = pq.read_table(args.flows).to_pylist()
    labeled = label_flows(rows, schedule, args.offset_minutes, args.pad_s)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(labeled), out)

    summary = qa_summary(labeled)
    if args.qa:
        qa_path = Path(args.qa)
        qa_path.parent.mkdir(parents=True, exist_ok=True)
        qa_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if args.csv:
        keys = {
            _canonical_key(row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"])
            for row in labeled
        }
        index: dict[tuple, list[tuple[datetime, str]]] = {}
        for csv_path in args.csv:
            for key, rows in load_csv_index(csv_path, keys).items():
                index.setdefault(key, []).extend(rows)
        report = crosscheck_flows(
            labeled, index, args.offset_minutes, tolerance_s=args.tolerance_s
        )
        if args.crosscheck:
            report_path = Path(args.crosscheck)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
