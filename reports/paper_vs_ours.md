# Bảng đối chiếu: Paper vs Baseline vs GTAE-IDS vs P1

> Số liệu đồng bộ với `results/*.csv` (retrain 2026-11-16). Mean ± std theo seed: [`seed_stats.md`](seed_stats.md). Đối chiếu paper ↔ code ↔ CSV của tác giả: [`../docs/REPRO_AUDIT.md`](../docs/REPRO_AUDIT.md) §5.

**Cập nhật:** 2026-11-29
**Đồ án:** NT204.R11.ANTN - Nhóm 8 - Tái hiện & Cải tiến GTAE-IDS
**Paper:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026-4041, 2025.

---

## 1. Bảng so sánh tổng hợp các phương pháp (p = 8)

| Phương pháp | Loại mô hình | Phân chia dữ liệu | Luật quyết định | TPR | FPR | AUROC | Ghi chú |
|---|---|---|---|---:|---:|---:|---|
| **Paper Table VI** | Graph Transformer AE | Snapshot (code: Friday 70/30) | Majority ($\ge 3/4$) | **99,04%** | **6,56%** | - | Khớp majority trên artifact hướng; OCSVM 4,03% |
| **CSV công khai của tác giả** | Notebook `GTAE_8pkt` (không chạy được như công bố) | Friday 70/30, mỗi lớp 1 đồ thị | Union (votes $\ge 1$) | 98,5-99,8% (theo lớp, = Table VII) | **13,12%** | - | `Final_Results_8pkt_Anomaly_Detection_2017.csv`; FPR ≠ 6,56% của paper |
| **B0: Raw Vector** | PyOD Detectors (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **0,50%** / **18,78%** @6,56 | **1,22%** / 6,56% | **0,698** | Ở cùng điểm FPR 6,56, B0 vượt M1 (11,54%) |
| **B1: MLP-AE** | Dense AE (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **6,29%** | **2,29%** | **0,595** | AE chuẩn nén 400d → 64d |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **4,18 ± 4,30%** | **2,79 ± 1,40%** | **0,594 ± 0,106** | Tái hiện đúng mô tả paper; phương sai seed lớn |
| **Tái tạo artifact hướng (T, $\ge 3/4$)** | GTAE + encoding lỗi của tác giả | Temporal T | Majority ($\ge 3/4$) | **99,22%** @ FPR 6,66% | 6,66% | - | Tái lập Table VI trong 0,2/0,1 pp; **chỉ đạt được khi tái tạo lỗi** (`results/direction_leak_votes.csv`) |
| **Tái tạo artifact hướng (P_paper, $\ge 3/4$)** | GTAE + encoding lỗi | Friday same-day | Majority ($\ge 3/4$) | **99,04%** @ FPR 5,50% | 5,50% | - | Seed 0; 95,58-99,04% qua 3 seed |
| **P_paper: M1 + Union (luật code)** | Graph Transformer AE | Friday CSV-row, test = paper Table VII | Union (votes $\ge 1$) | **3,25%** @ FPR 6,56% matched | **6,56%** | **0,478** | Dựng đúng Table VII: 30.041/33.228 edge; Heartbleed/Infiltration thiếu CSV; TPR@1% 1,39% |
| **P_paper: M1 + INNE** | Graph Transformer AE + INNE | Friday CSV-row, test = paper Table VII | Detector đơn | **8,31%** @ FPR 6,56% matched | **6,56%** | **0,590** | Detector tốt nhất trên `P_paper`; TPR@1% = 4,12% |
| **T sạch @ cùng điểm vận hành** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie | **11,54%** @ FPR 6,56% matched | **6,56%** | **0,594** | Đo bằng cùng pipeline `eval_paper_parity.py` |
| **P1: Bonferroni α=0,05** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **8,95%** | **3,64%** | **0,662** | TPR@FPR=1% = 0%; Fisher 47,53/18,86 không kiểm soát FPR |
| **A3: Reconstruction error** | GTAE decoder MSE | Temporal T (Sạch) | Threshold 99th pct | **6,01%** | **2,07%** | **0,649** | Cao hơn M1 ở cả p nhưng p=2/4 kèm FPR 6,31/3,51% |
| **A2: No LapPE** (Đề xuất A) | GTAE without PE | Temporal T (Sạch) | Ensemble tie | **6,36%** | **1,23%** | **0,682 ± 0,003** | AUROC ổn định theo seed; TPR@1% 12,46% |
| **B2: E-GraphSAGE-AE** (Đề xuất A) | Mean aggregation, cùng độ sâu/rộng | Temporal T (Sạch) | Ensemble tie | **9,78%** | **1,81%** | **0,689 ± 0,021** | Attention không cần thiết; TPR@1% 11,30% |
| **A5: Header hygiene** | GTAE, bỏ TTL + 2 checksum | Temporal T (Sạch) | Ensemble tie | **2,83%** | **2,33%** | **0,675** | Train lại 3 seed; TPR@1% **3,77%** ≥ M1 3,65%, AUROC 0,594 → 0,675 ⇒ không phải shortcut định danh |
| **Supervised RF cross-day (raw)** | Random Forest | Tue+Wed → Thu+Fri | Ngưỡng xác suất | **3,2-3,8%** @6,56 | 6,56% | **0,54** | Không phải upper bound; raw key theo ngày |
| **Supervised RF cross-day (`z`)** | Random Forest | Tue+Wed → Thu+Fri | Ngưỡng xác suất | **11,0-23,2%** @6,56 | 6,56% | **0,64-0,75** | Trần cross-day cao nhất đo được |
| **Supervised RF same-day (raw)** | Random Forest | Friday 70/30 | Ngưỡng xác suất | **99,9%** | 6,56% | **0,999** | Rò rỉ nhận diện phiên/ngày; không phải phương pháp hợp lệ |

*Ghi chú phương pháp:* các dòng **M1/Ours** dùng ngưỡng riêng của detector ở contamination 0,01 (FPR thực 2,79%). Các dòng ghi `@6,56` đặt ngưỡng trên benign test đúng 6,56%; `results/supervised_bound.csv` và `results/paper_parity/T_p8_selected.csv` là nguồn. Các dòng **@ FPR 6,56% matched** đặt ngưỡng sao cho FPR thực trên benign test đúng bằng 6,56% - cùng định nghĩa với paper - và grid contamination `[0,001; 0,01; 0,04; 0,05; 0,1]`. Cột FPR ở các dòng `P_paper`/`T sạch` là ngưỡng matched với FPR Ensemble công bố trong Table VI (6,56%), không phải FPR của một detector cụ thể. Số đo: `results/paper_parity/`, chi tiết: [`paper_parity.md`](paper_parity.md).

---

## 2. Kết quả Proposal P1 (Conformal Calibration & Early Exit)

Proposal P1 giải quyết 3 hạn chế thực tế của GTAE-IDS:
1. Chuẩn hóa điểm bất thường thành **conformal p-value**; Bonferroni kiểm soát FPR theo lý thuyết, Fisher chỉ exploratory khi detector tương quan.
2. Cơ chế **Early-Exit**: dừng kiểm tra ngay khi p-value $\le \alpha_p$, không cần chờ đủ 8 gói tin.
3. Đo lường chỉ số **Average Packets to Decision (APD)** và độ trôi phân phối thời gian (temporal drift).

*Bảng kết quả trung bình 3 seed trên tập kiểm thử chuẩn T_fixed (30.907 flow), calibration 40% = 800 flow. Chi tiết sinh tự động: [`P1.md`](P1.md).*

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) | AUROC | TPR@FPR=1% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0,01 | Bonferroni | 0,00% | 0,00% | 8,00 pkts | 8,00 pkts | 0,00% | 0,66 | 0,00% |
| 0,05 | Bonferroni | **8,95%** | **3,64%** | 7,75 pkts | 7,91 pkts | 7,70% | 0,66 | 0,00% |
| 0,10 | Bonferroni | **14,11%** | **5,78%** | 7,56 pkts | 7,84 pkts | 13,22% | 0,66 | 0,00% |
| 0,01 | Fisher | 42,46% | 13,57% | 6,44 pkts | 7,41 pkts | 41,57% | 0,64 | 2,77% |
| 0,05 | Fisher | **47,53%** | **18,86%** | **6,24 pkts** | 7,23 pkts | **46,98%** | 0,64 | 2,77% |
| 0,10 | Fisher | 49,33% | 22,96% | 6,16 pkts | 7,08 pkts | 48,58% | 0,64 | 2,77% |

**Nhận xét:**
- Với **Bonferroni ($\alpha = 0,05$)**, FPR thực đo **3,64%** ($\le 5\%$) và TPR **8,95%**, cao hơn M1 (4,18% @ 2,79%) ở vùng FPR tương đương. Ở $\alpha=0,10$, TPR **14,11%** @ FPR **5,78%**.
- Với **Bonferroni ($\alpha = 0,01$)**, TPR/FPR đều 0 vì sàn p-value $4/801 = 0,004994 > 0,01/7$; cấu hình này không thể alert với 800 calibration flow.
- Với **Fisher**, TPR tăng lên **42,46-49,33%** nhưng FPR **13,57-22,96%**, vượt xa $\alpha$ do 4 detector tương quan. Fisher chỉ nên đọc như exploratory, không dùng để claim kiểm soát FPR.
- **Giới hạn:** tại FPR=1%, Bonferroni đạt TPR 0% và Fisher 2,77%, đều thấp hơn M1 (3,65%). P1 chưa vượt M1 ở vùng FPR thấp; đóng góp là operating point có kiểm soát FPR và phân tích trade-off.
- **Early-exit:** Bonferroni $\alpha=0,05$ phát hiện sớm **7,70%** attack, APD **7,75 gói**; $\alpha=0,10$ phát hiện sớm **13,22%**, APD **7,56 gói**. Fisher giảm APD mạnh hơn (6,24 gói) nhưng FPR quá cao.


---

## 3. Đối chiếu từng bảng số liệu của paper

### 3.1 Table VI - đường cong theo p (p = 2..8)

Paper báo TPR/FPR tại contamination của họ; nhóm báo TPR tại **cùng FPR benign test = 6,56%**
(trừ paper FPR dao động 5,91-8,94%). Nguồn: `results/paper_parity/{T_,}p*_selected.csv`.

| p | Paper TPR / FPR | `T` TPR @6,56 (AUROC) | `P_paper` TPR @6,56 (AUROC) |
|---:|---:|---:|---:|
| 2 | 84,47 / 8,94 | 10,22 (0,505) | 3,79 (0,429) |
| 3 | 91,02 / 7,61 | 8,37 (0,504) | 12,47 (0,566) |
| 4 | 94,72 / 6,60 | 19,67 (0,578) | 5,36 (0,468) |
| 5 | 97,16 / 6,84 | 11,48 (0,678) | 1,10 (0,412) |
| 6 | 98,44 / 6,73 | **33,77** (0,835) | 5,40 (0,394) |
| 7 | 98,72 / 5,91 | 19,99 (0,711) | 26,77 (0,513) |
| 8 | **99,04 / 6,56** | 11,54 (0,594) | 3,25 (0,478) |

Paper tăng đơn điệu 84,47 -> 99,04; nhóm **không đơn điệu** (đỉnh p=6 rồi giảm). Khoảng cách
TPR tại p=8: 8,6x (`T`) và 30x (`P_paper`) nếu so với 99,04%.

### 3.2 Table VII - per-class, p = 8

Paper đo trên đồ thị **chỉ có một lớp tấn công**; nhóm đo trên đồ thị trộn `P_paper` với
ngưỡng contamination đã chọn (calib FPR ~6,56%), luật OR của code. Nguồn:
`results/paper_parity/p8_per_class.csv`.

| Lớp | Paper | `P_paper` OR | `P_paper` tie |
|---|---:|---:|---:|
| DoS Hulk | 98,74 | 7,57 | 0,58 |
| DoS GoldenEye | 99,08 | 7,65 | 0,75 |
| DoS Slowhttptest | 99,79 | 6,43 | 0,76 |
| DoS Slowloris | 99,60 | 8,55 | 2,00 |
| PortScan | 98,50 | 28,56 | 25,31 |
| DDoS | 99,34 | 9,23 | 0,61 |
| FTP-Patator | 98,85 | 6,32 | 1,72 |
| SSH-Patator | 98,86 | 5,52 | 0,19 |
| Web Attack - Brute Force | 99,29 | 5,71 | 0,48 |
| Heartbleed | 99,52 | 33,33 (n=11) | 0,00 |
| Infiltration | 99,83 | 0,98 (n=34) | 0,98 |

Lưu ý: paper có 1.468 cạnh Heartbleed và 1.764 cạnh Infiltration; CSV công khai chỉ cho phép
dựng 11 và 34 luồng khớp pcap, nên hai lớp này không thể so sánh trực tiếp.

### 3.3 Table X - ablation "có/không graph context"

| | OCSVM | IForest | HBOS | INNE | Ensemble |
|---|---:|---:|---:|---:|---:|
| Paper, không context | 95,81 | 88,45 | 90,01 | 95,34 | 96,75 |
| Paper, có GTAE | 98,46 | 96,66 | 97,73 | 96,47 | 99,04 |
| Nhóm, B0 raw (FPR 1,22%) | - | - | - | - | 0,50 |
| Nhóm, M1 GTAE (FPR 2,79%) | - | - | - | - | 4,18 |
| Nhóm, B0 raw @FPR 6,56% | - | - | - | - | **18,78** |
| Nhóm, M1 @FPR 6,56% | - | - | - | - | 11,54 |

Paper nói graph context +2,29 pp ensemble; nhóm đo **ngược lại**: B0 (không graph) 18,78 >
M1 11,54 ở cùng FPR, AUROC 0,698 > 0,594. Con số "không context 96,75" của paper chỉ tái lập
được với artifact hướng.

### 3.4 Table VIII/IX - chuyển miền

| Bộ | Paper | Nhóm | Ghi chú |
|---|---:|---:|---|
| CIC-IDS2018 p=8 | 98,74% (test chỉ tấn công) | 5,99% @ FPR 1,52% | Nhóm thêm 5.000 benign; AUROC 0,764 |
| ACI-IoT-2023 p=8 | 98,21% (test chỉ tấn công) | 1,69% @ FPR 1,11% | AUROC 0,536; benign ngày khác |
| ACI PortScan | 99,67% | 2,66% | Table IX |
| ACI Slowloris | 99,56% | 1,76% | Table IX |

### 3.5 Chi phí "real-time"

| | Paper | Nhóm |
|---|---:|---:|
| Model-only | 1,28 us/gói | 1.663 us/gói |
| End-to-end | - | 15.272 us/gói |
| Throughput | - | 8,2 flow/s (lưu lượng đến 12,1 flow/s) |

### 3.6 Ưu/nhược so với các bài cùng protocol

So sánh có kiểm soát (cùng `T`, p=8, 3 seed): B2 E-GraphSAGE-AE 9,78/1,81/0,689; A2 bỏ LapPE
6,36/1,23/0,682; B1 MLP-AE 6,29/2,29/0,595; A3 recon 6,01/2,07/0,649; M1 4,18/2,79/0,594.
Các baseline mạnh hơn M1 ở AUROC/TPR, tức attention + LapPE không phải nguồn tín hiệu.
