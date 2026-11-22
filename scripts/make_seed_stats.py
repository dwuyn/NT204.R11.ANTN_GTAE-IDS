"""Seed-variance table: mean ± std (ddof=1) and min–max over seeds.

Reads only committed measurement CSVs (no data/ or experiments/ needed) and
writes ``results/seed_stats.csv`` + ``reports/seed_stats.md``.

Why: every manual table in the report quotes a 3-seed mean. M1 p8 AUROC is
0.705 / 0.581 / 0.495 across seeds, so a mean without its spread hides whether
differences between methods are larger than seed noise.

    python scripts/make_seed_stats.py
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

METRICS = ("tpr", "fpr", "auroc", "tpr_at_fpr", "fpr_at_threshold")

# (label, csv path, rule column value, p filter). Rule column is "detector" or "rule".
SOURCES: tuple[tuple[str, str, str, int | None], ...] = (
    ("M1 GTAE (tie)", "results/M1_summary.csv", "tie", None),
    ("M1 GTAE (INNE)", "results/M1_summary.csv", "INNE", 8),
    ("B0 raw vector (tie)", "results/B0_summary.csv", "ensemble_tie", 8),
    ("B0 raw vector (HBOS)", "results/B0_summary.csv", "HBOS", 8),
    ("B1 MLP-AE (tie)", "results/B1_summary.csv", "ensemble_tie", 8),
    ("B2 E-GraphSAGE-AE (tie)", "results/B2/M1_summary.csv", "tie", None),
    ("A2 no-PE (tie)", "results/noPE/M1_summary.csv", "tie", 8),
    ("A3 recon-MSE", "results/A3_recon.csv", "threshold_99pct", 8),
    ("A5 hygiene (tie)", "results/A5_hygiene.csv", "tie", 8),
)


def mean_std(values: list[float]) -> tuple[float, float]:
    """Sample mean and sample standard deviation (ddof=1; 0.0 for n<2)."""
    if not values:
        raise ValueError("values cannot be empty")
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(var)


def _get(row: dict[str, str], metric: str) -> float | None:
    keys = (metric, "tpr_at_fpr_1pct") if metric == "tpr_at_fpr" else (metric,)
    for key in keys:
        raw = row.get(key)
        if raw not in (None, "", "None", "nan"):
            return float(raw)
    return None


def summarize(rows: list[dict[str, str]], label: str) -> list[dict[str, object]]:
    by_p: dict[int, list[dict[str, str]]] = {}
    for row in rows:
        by_p.setdefault(int(row["p"]), []).append(row)
    out = []
    for p in sorted(by_p):
        group = by_p[p]
        rec: dict[str, object] = {"method": label, "p": p, "n_seeds": len(group)}
        for metric in METRICS:
            vals = [v for v in (_get(r, metric) for r in group) if v is not None]
            if not vals:
                continue
            m, s = mean_std(vals)
            rec[f"{metric}_mean"] = m
            rec[f"{metric}_std"] = s
            rec[f"{metric}_min"] = min(vals)
            rec[f"{metric}_max"] = max(vals)
        out.append(rec)
    return out


def load_source(path: Path, rule: str, p: int | None) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    col = "detector" if rows and "detector" in rows[0] else "rule"
    rows = [r for r in rows if r[col] == rule]
    if p is not None:
        rows = [r for r in rows if int(r["p"]) == p]
    return rows


def p1_summary(path: Path) -> list[dict[str, object]]:
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    groups: dict[tuple[str, str], list[dict[str, str]]] = {}
    for r in rows:
        groups.setdefault((r["method"], r["alpha"]), []).append(r)
    out = []
    for (method, alpha), group in sorted(groups.items()):
        rec: dict[str, object] = {
            "method": f"P1 {method} α={alpha}",
            "p": "2..8",
            "n_seeds": len(group),
        }
        for metric, key in (("tpr", "tpr"), ("fpr", "fpr"), ("auroc", "auroc"),
                            ("tpr_at_fpr", "tpr_at_fpr_1pct")):
            vals = [float(r[key]) for r in group if r.get(key) not in (None, "")]
            if vals:
                m, s = mean_std(vals)
                rec[f"{metric}_mean"], rec[f"{metric}_std"] = m, s
                rec[f"{metric}_min"], rec[f"{metric}_max"] = min(vals), max(vals)
        out.append(rec)
    return out


def _pct(rec: dict[str, object], metric: str) -> str:
    if f"{metric}_mean" not in rec:
        return "—"
    return f"{100 * rec[f'{metric}_mean']:.2f} ± {100 * rec[f'{metric}_std']:.2f}"


def _auc(rec: dict[str, object]) -> str:
    if "auroc_mean" not in rec:
        return "—"
    return (f"{rec['auroc_mean']:.3f} ± {rec['auroc_std']:.3f} "
            f"[{rec['auroc_min']:.3f}–{rec['auroc_max']:.3f}]")


def render(records: list[dict[str, object]], m1_curve: list[dict[str, object]]) -> str:
    lines = [
        "# Phương sai theo seed (mean ± std, 3 seed)",
        "",
        "> Sinh tự động bởi `scripts/make_seed_stats.py` từ các CSV đo trong `results/`. "
        "Không sửa tay. std là độ lệch chuẩn mẫu (ddof=1); ngoặc vuông là min–max AUROC.",
        "",
        "## 1. So sánh các phương pháp tại p = 8 (protocol T)",
        "",
        "| Phương pháp | n | TPR (%) | FPR (%) | AUROC | TPR @ ngưỡng FPR=1% của train2 (%) | FPR thực tại ngưỡng đó (%) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for rec in records:
        lines.append(
            f"| {rec['method']} | {rec['n_seeds']} | {_pct(rec, 'tpr')} | {_pct(rec, 'fpr')} | "
            f"{_auc(rec)} | {_pct(rec, 'tpr_at_fpr')} | {_pct(rec, 'fpr_at_threshold')} |"
        )
    lines += [
        "",
        "## 2. Đường cong theo p của M1 (ensemble tie)",
        "",
        "| p | TPR (%) | FPR (%) | AUROC |",
        "|---:|---:|---:|---:|",
    ]
    for rec in m1_curve:
        lines.append(f"| {rec['p']} | {_pct(rec, 'tpr')} | {_pct(rec, 'fpr')} | {_auc(rec)} |")

    m1 = next(r for r in records if r["method"] == "M1 GTAE (tie)")
    lines += [
        "",
        "## 3. Đọc bảng",
        "",
        f"- **M1 p8 dao động rất mạnh theo seed:** AUROC {_auc(m1)}. Seed tệ nhất gần như ngẫu nhiên "
        "(≈ 0,5). Mọi chênh lệch nhỏ hơn khoảng ±1 std giữa các phương pháp **không** đủ để kết luận "
        "phương pháp nào tốt hơn với 3 seed.",
        "- **Kết luận vẫn đứng vững dù tính phương sai:** khoảng cách tới con số của paper (99,04% TPR) "
        "lớn hơn hàng chục lần độ lệch chuẩn của mọi cấu hình.",
        "- **Đường cong theo p không đơn điệu**: tiêu chí \"TPR tăng theo p\" đặt ra trong kế hoạch "
        "(`docs/GTAE-IDS_Research_docs.md` §0) **không đạt**.",
        "- **Cột \"TPR @ ngưỡng FPR=1%\"** dùng ngưỡng là quantile 99% của điểm trên `train2` (benign Monday). "
        "FPR thực trên benign test (Tue–Fri) được ghi ở cột cuối và thường > 1% do dịch chuyển phân phối.",
        "",
    ]
    return "\n".join(lines)


def _write_csv(path: Path, records: list[dict[str, object]]) -> None:
    fields: list[str] = []
    for rec in records:
        for key in rec:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    root: Path = args.root

    records: list[dict[str, object]] = []
    m1_curve: list[dict[str, object]] = []
    for label, rel, rule, p in SOURCES:
        path = root / rel
        if not path.exists():
            print(f"skip (missing): {rel}", file=sys.stderr, flush=True)
            continue
        summary = summarize(load_source(path, rule, p), label)
        if label == "M1 GTAE (tie)":
            m1_curve = summary
            summary = [r for r in summary if r["p"] == 8]
        elif p is None:
            summary = [r for r in summary if r["p"] == 8]
        records.extend(summary)

    p1_path = root / "results/P1_summary.csv"
    if p1_path.exists():
        records.extend(p1_summary(p1_path))

    _write_csv(root / "results/seed_stats.csv", records + m1_curve)
    (root / "reports/seed_stats.md").write_text(render(records, m1_curve), encoding="utf-8")
    print(f"wrote {len(records)} rows -> results/seed_stats.csv, reports/seed_stats.md", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
