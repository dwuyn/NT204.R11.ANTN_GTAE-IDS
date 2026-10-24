#!/usr/bin/env python3
"""Generate reports/graph_stats.md from data/graphs/*/summary.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAPHS = REPO_ROOT / "data" / "graphs"
OUT = REPO_ROOT / "reports" / "graph_stats.md"


def load(split: str) -> dict:
    return json.loads((GRAPHS / split / "summary.json").read_text(encoding="utf-8"))


def main() -> int:
    lines = [
        "# Graph statistics",
        "",
        "Sinh tự động bởi `scripts/make_graph_stats.py` từ "
        "`data/graphs/{T,R}/summary.json`.",
        "",
    ]
    for split, title in (
        ("T", "Protocol T (temporal)"),
        ("R", "Protocol R (random)"),
        ("T_fixed", "Fixed population (flow ≥ 8 packets)"),
    ):
        summary = load(split)
        lines += [f"## {title}", ""]
        lines += [
            "| p | train1 | train2 | test | benign | attack | nodes |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for key in sorted(summary, key=lambda k: int(k[1:])):
            test = summary[key]["test"]
            lines.append(
                f"| {key[1:]} | {summary[key]['train1']['edges']:,} | "
                f"{summary[key]['train2']['edges']:,} | {test['edges']:,} | "
                f"{test['benign']:,} | {test['attack']:,} | {test['nodes']:,} |"
            )

        lines += ["", "### Attack types trong test", ""]
        for key in sorted(summary, key=lambda k: int(k[1:])):
            types = summary[key]["test"]["attack_types"]
            lines.append(f"**p={key[1:]}**")
            lines.append("")
            lines.append("| Attack type | Edges |")
            lines.append("|---|---:|")
            for attack, count in sorted(types.items(), key=lambda kv: (-kv[1], kv[0])):
                flag = " ⚠️" if count < 50 else ""
                lines.append(f"| {attack} | {count:,}{flag} |")
            lines.append("")
        lines.append("⚠️ = dưới 50 mẫu; không nên báo per-class TPR cho lớp này.")
        lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
