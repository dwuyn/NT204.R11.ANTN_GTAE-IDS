# Ablation và baseline (sinh tự động)

**Nguồn:** `results/M1_summary.csv`, `results/B0_summary.csv`, `results/B1_summary.csv`, `results/A3_recon.csv`, `results/noPE/M1_summary.csv` (A2 no-PE), `results/B2/M1_summary.csv` (B2 E-GraphSAGE-AE), `results/A5_hygiene.csv` (A5 hygiene).

**Quy ước:** TPR/FPR là mean theo seed. `A3_recon` dùng ngưỡng 99th percentile của reconstruction error trên `train2`; cột `FPR@threshold` là FPR thực trên test tại ngưỡng đó, không phải FPR=1%.

## 1. M1 vs A3 reconstruction-error

| p | M1 TPR | M1 FPR | M1 AUROC | A3 TPR | A3 FPR | A3 AUROC | ΔTPR (A3−M1) |
|---:|---|---:|---:|---|---:|---:|---:|
| 2 | 3.30% ± 1.70% | 2.89% | 0.505 | 6.23% ± 0.99% | 6.31% | 0.425 | +2.92 pp |
| 3 | 4.18% ± 1.93% | 2.80% | 0.504 | — | — | — | — |
| 4 | 8.56% ± 2.64% | 2.94% | 0.578 | 12.15% ± 1.61% | 3.51% | 0.519 | +3.59 pp |
| 5 | 6.31% ± 5.40% | 2.62% | 0.678 | — | — | — | — |
| 6 | 14.93% ± 10.87% | 2.29% | 0.835 | — | — | — | — |
| 7 | 6.90% ± 11.87% | 2.55% | 0.711 | — | — | — | — |
| 8 | 4.18% ± 4.30% | 2.79% | 0.594 | 6.01% ± 9.69% | 2.07% | 0.649 | +1.82 pp |

## 2. Baseline p=8

| Experiment | TPR | FPR | AUROC | TPR@calib-threshold | FPR@threshold |
|---|---:|---:|---:|---:|---:|
| M1 | 4.18% | 2.79% | 0.594 | 3.65% | 2.30% |
| A3_recon | 6.01% | 2.07% | 0.649 | 6.01% | 2.07% |
| B0 | 0.50% | 1.22% | 0.698 | 2.13% | 1.58% |
| B1 | 6.29% | 2.29% | 0.595 | 6.95% | 2.52% |
| A2_noPE | 6.36% | 1.23% | 0.682 | 12.46% | 2.36% |
| B2 | 9.78% | 1.81% | 0.689 | 11.30% | 2.20% |
| A5_hygiene | 2.83% | 2.33% | 0.675 | 3.77% | 1.58% |

## 3. A5 header-hygiene: per-detector

A5 zeroes TTL + IP/TCP checksums (5 of the 25 kept bytes) and retrains; the ensemble row alone is not enough to read it, because one detector can lose its histogram resolution and drag the vote with it.

| detector | M1 AUROC (p8) | A5 AUROC (p8) | ΔAUROC | M1 TPR@FPR=1% | A5 TPR@FPR=1% |
|---|---:|---:|---:|---:|---:|
| IForest | 0.601 | 0.677 | +0.076 | 3.12% | 3.16% |
| OCSVM | 0.595 | 0.672 | +0.077 | 0.10% | 2.40% |
| HBOS | 0.543 | 0.673 | +0.130 | 7.35% | 2.96% |
| INNE | 0.578 | 0.636 | +0.058 | 4.80% | 0.84% |

**Cảnh báo đo lường:** HBOS chia mỗi chiều embedding thành histogram `n_bins` khoảng đều; embedding sau khi mask header (A5) có nhiều chiều chỉ còn 3–6 giá trị float32 phân biệt nên `n_bins=20` không dựng được histogram (numpy từ chối). `src.detectors.fit_detectors` vì thế tự hạ số bin (và bỏ chiều không chia được), ghi lại trong `detector_fit_notes` của từng run. Hàng HBOS và ensemble của các run đó KHÔNG so sánh trực tiếp được với M1 về cấu hình detector; đọc IForest/OCSVM/INNE cho kết luận hygiene, và đọc bảng n_bins dưới đây trước khi so ensemble.

| run | detector | n_bins | lý do |
|---|---|---:|---|
| A5_p8_seed0 | HBOS | 3 | embedding columns too sparse/degenerate to bin |
| M1_p8_seed2 | HBOS | 3 | embedding columns too sparse/degenerate to bin |

## 4. Đọc kết quả

- A3 là detector chỉ dùng reconstruction MSE; không fit PyOD.
- So sánh phải cùng p/seed và cùng operating point; `FPR@threshold` khác nhau nên không được chỉ so TPR.
- Nếu A3 vượt M1 ở cùng FPR, đó là bằng chứng đồ thị/decoder có tín hiệu; nếu không, ghi nhận trung thực.

```bash
python scripts/eval_recon_ablation.py --graphs data/graphs/T --models experiments/T --ps 2 4 8 --seeds 0 1 2
python scripts/make_ablation_report.py
```
