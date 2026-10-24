#!/usr/bin/env python3
"""Generate reports/qa_labeling.md from the per-day QA/cross-check JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
PROCESSED = REPO_ROOT / "data" / "processed"
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")


def load(name: str) -> dict:
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def load_parse(day: str) -> dict:
    return json.loads(
        (PROCESSED / f"parse_summary_{day}.json").read_text(encoding="utf-8")
    )


def main() -> int:
    lines = [
        "# QA labeling — CIC-IDS2017",
        "",
        "Sinh tự động bởi `scripts/make_qa_report.py`. Nguồn: "
        "`reports/qa_labeling_{day}.json`, `reports/crosscheck_{day}.json`, "
        "`data/processed/parse_summary_{day}.json`.",
        "",
        "## 1. Parse",
        "",
        "| Ngày | Gói đọc | Flow | Packet rows | RST flows | Idle split | Reopened |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for day in DAYS:
        summary = load_parse(day)
        c = summary["counters"]
        lines.append(
            f"| {day} | {c['packets_read']:,} | {summary['flows_written']:,} | "
            f"{summary['packets_written']:,} | {c.get('flows_with_rst', 0):,} | "
            f"{c.get('flows_idle_timeout', 0):,} | {c.get('flows_reopened', 0):,} |"
        )

    lines += [
        "",
        "## 2. Nhãn",
        "",
        "| Ngày | Flows | Benign | Attack | UNCERTAIN | UNCERTAIN % | Khớp CSV | Đồng thuận |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    qas = {}
    ccs = {}
    for day in DAYS:
        qa = load(f"qa_labeling_{day}.json")
        cc = load(f"crosscheck_{day}.json")
        qas[day] = qa
        ccs[day] = cc
        lines.append(
            f"| {day} | {qa['total_flows']:,} | {qa['benign']:,} | {qa['attack']:,} | "
            f"{qa['uncertain']:,} | {qa['uncertain_rate']:.2%} | "
            f"{cc['match_rate']:.2%} | {cc['agreement']:.2%} |"
        )

    lines += [
        "",
        "Ngưỡng QA của design doc: `UNCERTAIN ≤ 2%`; bất đồng lịch-vs-CSV > 5% phải giải thích.",
        "",
        "### Confusion với CSV",
        "",
        "| Ngày | TN | FP | FN | TP |",
        "|---|---:|---:|---:|---:|",
    ]
    for day in DAYS:
        c = ccs[day]["confusion"]
        lines.append(f"| {day} | {c['tn']:,} | {c['fp']:,} | {c['fn']:,} | {c['tp']:,} |")

    lines += ["", "### Attack types", "", "| Ngày | Loại tấn công | Số flow |", "|---|---|---:|"]
    for day in DAYS:
        for attack, count in qas[day]["attack_types"].items():
            lines.append(f"| {day} | {attack} | {count:,} |")

    lines += [
        "",
        "## 3. Ghi chú kỹ thuật",
        "",
        "- **Múi giờ:** hiệu chuẩn từ 510 flow smoke khớp CSV → `utc_offset_minutes = -180` (UTC−3).",
        "- **CSV CIC bị lỗi AM/PM:** cross-check thử `t`, `t+12h`, `t−12h`; tolerance 120 s vì CSV chỉ có phút.",
        "- **Infiltration lateral (192.168.10.8 → LAN)** đã loại khỏi nhãn chính: CSV label BENIGN, "
        "paper Table VII chỉ có 1.764 cạnh; giữ lại sẽ tạo ~71k FP.",
        "- **PortScan** dùng cửa sổ gộp 13:55–14:35 và 14:51–15:29; từng burst cho đồng thuận thấp hơn.",
        "- **Pad 60 s**; pad nhỏ (0/5/15 s) làm FN tăng mạnh.",
        "- **Heartbleed chỉ 1 flow** (một phiên dài 20 phút); per-class TPR của Heartbleed không có ý nghĩa thống kê.",
        "- **PortScan p=8 chỉ 204 flow** vì scan toàn flow 1–2 gói; TPR(p=8) của PortScan có mẫu nhỏ.",
        "",
    ]
    out = REPORTS / "qa_labeling.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
