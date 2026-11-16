# Online latency (sinh tự động)

**Nguồn:** `results/latency_summary.json` (+ `results/latency.csv`, `results/early_exit_timing.csv`). Chạy lại bằng `python scripts/eval_latency.py --mode stream ...`.

**Định nghĩa (docs/DECISIONS.md §4):** "real-time" = wall clock per flow từ lúc flow đóng đến lúc có alert, trên replay pcap thật. Stage: `graph` (expire + add + dựng edge matrix), `line` (line graph), `pe` (Laplacian PE, 0 khi no-PE), `forward` (encoder), `detector` (4 detector trên 1 embedding).

## 1. Replay end-to-end

Mỗi flow trong pcap đều được parse và đưa vào cửa sổ; chi phí end-to-end chỉ được đo trên mỗi flow thứ `K` (`sample_every`) vì dựng lại transformer trên toàn cửa sổ cho từng flow là bất khả thi về thời gian (xem mục 5).

| mode | p | seed | flows replayed | K | flows đo | stale | cửa sổ (s) | edges/flow (mean/p95) | wall (s) | flows/s replay | flows/s detect | µs/packet | metrics_valid |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| no_pe | 8 | 0 | 349,256 | 100 | 3,492 | 3,116 | 120 | 216.7 / 1,757.3 | 681 | 512.6 | 8.2 | 15272.2 | yes |
| window_pe | 8 | 0 | 80,000 | 1000 | 80 | 41 | 120 | 918.3 / 2,156.8 | 272 | 294.5 | 3.8 | 32468.3 | yes |

## 2. Stage latency (µs/flow)

| mode | stage | mean | p50 | p95 | p99 |
|---|---|---:|---:|---:|---:|
| no_pe | graph | 115.1 | 64.7 | 493.6 | 644.2 |
| no_pe | line | 72,389.1 | 6,263.0 | 448,377.4 | 456,113.6 |
| no_pe | pe | 0.3 | 0.2 | 0.6 | 0.8 |
| no_pe | forward | 13,298.5 | 2,759.0 | 90,746.6 | 130,927.7 |
| no_pe | detector | 36,344.5 | 36,022.8 | 39,336.0 | 43,389.7 |
| no_pe | **total** | **122,177.8** | 47,975.2 | 488,013.6 | 499,737.5 |
| window_pe | graph | 622.7 | 352.5 | 2,306.8 | 3,581.5 |
| window_pe | line | 25,432.6 | 4,384.5 | 27,454.5 | 435,530.5 |
| window_pe | pe | 87,007.0 | 50,539.6 | 226,945.8 | 486,464.8 |
| window_pe | forward | 108,508.7 | 114,512.8 | 165,343.6 | 176,354.0 |
| window_pe | detector | 38,017.7 | 37,191.0 | 44,444.4 | 50,482.7 |
| window_pe | **total** | **259,746.1** | 201,015.9 | 594,690.0 | 909,241.4 |

**Stale vs fresh (quan trọng cho cách đọc):** một flow được chấm tại `t_last` của chính nó; nếu `t_last` đã lùi quá cửa sổ so với mốc thời gian lớn nhất đã thấy (`watermark`), nó là flow đóng do hết capture (hoặc idle timeout) và cửa sổ của nó không còn chứa bản thân nó. Tách hai nhóm này ra:

| mode | nhóm | n | mean | p50 | p95 | p99 |
|---|---|---:|---:|---:|---:|---:|
| no_pe | fresh | 376 | 129,411.6 | 118,427.5 | 197,736.0 | 528,691.6 |
| no_pe | stale | 3,116 | 121,304.9 | 47,183.5 | 488,062.9 | 497,718.7 |
| window_pe | fresh | 39 | 281,095.2 | 201,962.4 | 529,136.7 | 1,177,203.5 |
| window_pe | stale | 41 | 239,438.5 | 198,859.0 | 593,061.7 | 647,681.3 |


## 3. Streaming vs offline

| mode | rule | streaming TPR | streaming FPR | streaming AUROC | offline T TPR (p8, 3 seed mean) | offline FPR |
|---|---|---:|---:|---:|---|---:|
| no_pe | tie | 0.08% | 0.91% | 0.717 | **4.18%** | **2.79%** |
| no_pe | strict | 0.08% | 0.34% | 0.717 | **4.18%** | **2.79%** |
| window_pe | tie | 0.00% | 0.00% | 0.287 | **4.18%** | **2.79%** |
| window_pe | strict | 0.00% | 0.00% | 0.287 | **4.18%** | **2.79%** |

**Đọc bảng này:** streaming metrics KHÔNG phải phép đo offline, vì ba lý do phải đọc cùng nhau:

1. **Quần thể khác.** Streaming chỉ replay thứ Sáu; offline `T` là test Thứ Ba–Thứ Sáu. Tỷ lệ tấn công và thành phần lớp khác nhau.
2. **Đồ thị khác.** Mỗi flow được chấm trên cửa sổ trượt của nó, không phải trên đồ thị tĩnh của split; embedding khác M1 theo thiết kế.
3. **Không hiệu chỉnh lại ngưỡng.** 4 detector được fit trên embedding `train2` offline và áp nguyên ngưỡng (`threshold_`) lên embedding cửa sổ. Vì vậy cột TPR/FPR đo *khả năng chuyển ngưỡng*, không phải năng lực tối đa; **AUROC là cột thông tin** vì nó bất biến với ngưỡng.

Kết luận cần kiểm tra: streaming còn giữ thứ hạng (AUROC không sụp về 0.5) thì biểu diễn cửa sổ vẫn dùng được, ngay cả khi ngưỡng phải hiệu chỉnh lại trên dữ liệu cửa sổ.

## 4. Early-exit (P1) cost

Chi phí mỗi flow = tổng forward cost của các bước p đã dùng trước khi ra quyết định (`EarlyExitResult.p_decision`). Forward cost mỗi bước đo bằng batch 4096 trên ma trận edge test thật, không phải suy ra từ APD.

| alpha | seed | method | p_decision median | p_decision mean | µs/flow mean | µs/flow p95 | early-exit rate (attack) | TPR | FPR |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 0.05 | 0 | bonferroni | 8 | 8 | 128.0 | 128.0 | 0.00% | 0.00% | 0.00% |
| 0.1 | 0 | bonferroni | 8 | 7.451 | 108.0 | 128.0 | 20.48% | 22.29% | 6.14% |
| 0.05 | 1 | bonferroni | 8 | 8 | 115.5 | 115.5 | 0.00% | 0.00% | 0.00% |
| 0.1 | 1 | bonferroni | 8 | 7.814 | 109.7 | 115.5 | 8.89% | 9.01% | 3.58% |
| 0.05 | 2 | bonferroni | 8 | 8 | 112.3 | 112.3 | 0.00% | 0.00% | 0.00% |
| 0.1 | 2 | bonferroni | 8 | 7.587 | 101.5 | 112.3 | 12.00% | 12.14% | 5.50% |

Chi phí này chỉ gồm encoder forward; detector và cửa sổ đồ thị là hằng số theo p nên không đổi giữa các bước.

**Chia tách calibration:** mode này dùng đúng split của `src.eval` (`calibration_fraction = 0.2` → `n_calib = 400`), nên sàn Bonferroni `4/401 ≈ 0.00998` lớn hơn `α/K = 0.05/7 ≈ 0.00714`: ở α = 0.05 **không thể** alert, và bảng dưới đúng là 0. P1 công bố (`results/P1_summary.csv`) dùng `calibration_fraction = 0.4` (800 flow) — đọc TPR/FPR ở đây là của split 0.2, còn cột thời gian là thứ cần lấy từ bảng này.
