# GTAE-IDS — Work Plan & Tiến độ (live)

**Cập nhật:** 2026-11-10
**Đồ án:** NT204.R11.ANTN — Nhóm B — Tái hiện & cải tiến GTAE-IDS
**Paper neo:** J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, "GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection," *IEEE TIFS*, vol. 20, pp. 4026–4041, 2025, doi: 10.1109/TIFS.2025.3557741.
**Tài liệu kỹ thuật chi tiết:** [`GTAE-IDS_Research_docs.md`](GTAE-IDS_Research_docs.md) — file này **thay thế trạng thái WBS §7** và là nguồn duy nhất theo dõi tiến độ.
**Kế hoạch mở rộng còn lại:** [`REMAINING_PLAN.md`](REMAINING_PLAN.md) — thứ tự ưu tiên, acceptance và lệnh bắt đầu cho ablation/B2/A3/G1/G2/H7.

> Quy ước: `[x]` = đã xong và đã verify; `[ ]` = chưa xong; `[~]` = xong một phần.
> Ước lượng công sức là **person-day**, dùng để xếp lịch, không phải cam kết.

---

## 0. Trạng thái tổng quan

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| **M1** | Chốt scope + design doc | `[x]` design doc xong; kiến trúc Table III, Fig 3/4 |
| **M2** | Data + parse + label QA + graph debug | `[x]` 5 ngày; đủ p=2..8 (T) + R (2,4,8) + T_fixed |
| **M3** | GTAE train được | `[x]` 21 model (p2–p8 × 3 seed); GPU T4 100 epoch |
| **M4** | Detectors + số liệu TPR/FPR | `[x]` M1 126 runs; chẩn đoán bản chất one-class AE |
| **M5** | So sánh paper + ablation + P1 | `[~]` B0, B1, P1 (calibration 40%), `reports/paper_vs_ours.md`; thiếu ablation/B2/A3 |
| **M6** | Báo cáo + slide + demo + bảo vệ | `[~]` report/slides/demo có; đang đồng bộ số P1, chưa tag |

**Tình trạng đồ án:** **ĐÃ HOÀN THÀNH PHẦN LỚN M1–M6**.
- Đã có báo cáo nghiên cứu chi tiết: [`reports/report.md`](../reports/report.md)
- Đã có slide thuyết trình Marp 14 slide: [`reports/slides.md`](../reports/slides.md)
- Đã có kịch bản và script demo 5 phút: [`demo/run_demo.sh`](../demo/run_demo.sh)
- Đã có tài liệu đối chứng 3 bên và phân tích mã nguồn gốc: [`reports/paper_vs_ours.md`](../reports/paper_vs_ours.md) & [`docs/REPRO_AUDIT.md`](REPRO_AUDIT.md)
- Đã có báo cáo P1 sinh tự động từ CSV: [`reports/P1.md`](../reports/P1.md)

**Còn lại trước khi chốt:** ablation A1–A6/B2, nhãn corrected Engelen (A3), tag H7; số P1 đã được đồng bộ lại theo `results/P1_summary.csv`.

**Không còn blocker kỹ thuật cho bản báo cáo hiện tại.** Toàn bộ 83 test pytest pass; các mục ablation/B2/A3 là mở rộng, không chặn báo cáo.
---

## 1. Quyết định đã chốt

| Hạng mục | Giá trị đã chọn | Ghi chú / bằng chứng |
|---|---|---|
| Scope | MUST + SHOULD + MAY | MAY = CIC-IDS2018 có benign, latency, header hygiene. **ACI-IoT-2023 ngoài scope** |
| Dataset chính | CIC-IDS2017, TCP/IPv4 | 5 pcap + `GeneratedLabelledFlows` |
| Repo | Repo này (`ids-proj`) | Không tái dùng parser Scapy của repo IDS cũ |
| Split chính | Temporal **T**: train Monday benign, test Tue–Fri | Random **R** chỉ để so paper |
| Compute | Preprocess local → train Kaggle | Upload `data/graphs` + code, không upload pcap |
| Nguồn nhãn | Lịch CIC + CSV là chính; Engelen corrected **eval-only** | Chưa triển khai phần corrected (task A3) |
| Múi giờ | `utc_offset_minutes = -180` (UTC−3) | Khớp 510 flow smoke với CSV (mode −180/−181) |
| Pad cửa sổ | 60 s | Pad 0/5/15 làm FN tăng mạnh |
| Dung sai join CSV | 120 s | CSV timestamp chỉ có độ phân giải phút + lỗi AM/PM |
| Infiltration lateral | **Loại khỏi nhãn chính** | CSV label BENIGN; paper Table VII chỉ 1.764 cạnh, giữ sẽ tạo 71k FP |
| PortScan windows | Gộp 13:55–14:35 và 14:51–15:29 | Đồng thuận 96,8% > 95,9% khi dùng từng burst |
| Kết thúc flow | FIN/RST **không** kết thúc ngay; tách khi idle >120 s hoặc SYN mới sau FIN/RST | Sửa lỗi 68% → 0,7% UNCERTAIN |
| Định dạng pcap | pcapng | CIC phát hành pcapng dù đuôi `.pcap` |
| Graph artifact | `.npz` + `day` cho từng edge | `flow_id` chỉ unique trong ngày; đã thêm `day` |
| P1 calibration | 40% của `train2` = 800 flow | 20% = 400 flow không đủ để Bonferroni α=0,05 alert; Fisher chỉ exploratory |
| Test | Không commit pcap; commit code/config/report | `data/`, `experiments/`, `*.pt`, `*.npy` bị ignore |

---

## 2. Đã hoàn thành (đã verify)

### 2.1 Dữ liệu

- [x] Tải đủ 5 pcap + `GeneratedLabelledFlows.zip`; tổng **51 GB**.
- [x] SHA256: **6/6 OK** (`data/raw/SHA256SUMS`).
- [x] Giải nén CSV 5 ngày (1,2 GB) vào `data/raw/GeneratedLabelledFlows/TrafficLabelling/`.

| Ngày | Flows | Packet rows lưu | Gói đọc |
|---|---:|---:|---:|
| Monday | 133.793 | 1.046.065 | 11.709.971 |
| Tuesday | 110.550 | 851.306 | 11.551.954 |
| Wednesday | 280.306 | 2.200.112 | 13.788.878 |
| Thursday | 170.872 | 937.490 | 9.322.025 |
| Friday | 349.256 | 1.785.920 | 9.997.874 |
| **Tổng** | **1.044.777** | **6.820.893** | **56.370.702** |

### 2.2 Parse + label + QA

- [x] Parser streaming pcap/pcapng, flow key 5-tuple, giữ 8 gói đầu, direction fwd/bwd.
- [x] Label theo lịch 18 cửa sổ + NAT + port dịch vụ.
- [x] Cross-check CSV với xử lý lỗi AM/PM (`t`, `t±12h`), tolerance 120 s.
- [x] Sinh [`reports/qa_labeling.md`](../reports/qa_labeling.md) tự động từ JSON.

| Ngày | Flows | Attack | UNCERTAIN | Khớp CSV | Đồng thuận |
|---|---:|---:|---:|---:|---:|
| Monday | 133.793 | 0 | 1,15% | 99,99% | 100,00% |
| Tuesday | 110.550 | 6.483 | 1,28% | 99,97% | 99,52% |
| Wednesday | 280.306 | 174.426 | 0,70% | 99,98% | 99,18% |
| Thursday | 170.872 | 2.057 | 1,46% | 99,95% | 99,86% |
| Friday | 349.256 | 255.745 | 1,75% | 99,94% | 96,82% |

### 2.3 Graph & split

- [x] `src/graph_builder.py`: edge arrays, node mapping `(IP,port)`, sample/cap, split T/R.
- [x] `src/line_graph.py`: line graph, K_max=32, self-loop, symmetrize.
- [x] `src/pe.py`: Laplacian PE k=8, edge PE = φu+φv.
- [x] Build **T** p=2..8, **R** p=2,4,8, **T_fixed** (flow ≥8 gói) p=2..8; tổng artifact **89 MB**.

| p | T train1 | T train2 | T test edges | T benign | T attack | T nodes |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 5.000 | 2.000 | 42.362 | 5.000 | 37.362 | 25.663 |
| 3 | 5.000 | 2.000 | 38.521 | 5.000 | 33.521 | 24.758 |
| 4 | 5.000 | 2.000 | 36.397 | 5.000 | 31.397 | 24.660 |
| 5 | 5.000 | 2.000 | 35.923 | 5.000 | 30.923 | 24.680 |
| 6 | 5.000 | 2.000 | 35.912 | 5.000 | 30.912 | 24.684 |
| 7 | 5.000 | 2.000 | 34.089 | 5.000 | 29.089 | 24.561 |
| 8 | 5.000 | 2.000 | 30.907 | 5.000 | 25.907 | 24.030 |

Protocol R dùng cùng bộ đếm test (cap 5.000/class) nhưng train1/train2 lấy benign từ cả 5 ngày và test có cả Monday; audit kiểm tra disjoint. `T_fixed` dùng **cùng tập flow ≥8 gói cho mọi p** (30.907 test edges), phục vụ so sánh TPR–p không đổi population.

### 2.4 Model & training

- [x] `src/model_gtae.py`: edge transformer 6 lớp (p=8), attention trên line graph, DNN decoder đúng Table III.
- [x] `src/train_gtae.py`: subgraph 2-hop ≤200 cạnh, batch 50, MSE toàn 50p, Adam lr=1e-3; **batched block-diagonal cho CUDA**, tuần tự cho CPU.
- [x] **21 model** p2..p8 × seed 0,1,2: p2–p5,p7,p8 trên Kaggle T4 (100 epoch, **10,6–18,0 s/run**, val MSE 0,022–0,041); p6 local CPU (dataset Kaggle p6 bị treo).
- [x] `src/embed.py`, `src/detectors.py`, `src/eval.py`: embedding + 4 detector + 2 luật vote + metrics.

### 2.5 Hạ tầng kiểm thử

- [x] **83 pytest** pass (thêm `test_p1.py`, `test_pe.py` deterministic, `test_leakage.py`, `test_detectors.py`).
- [x] `laplacian_pe` dùng ARPACK `v0` có seed; embedding tái lập tuyệt đối giữa hai lần chạy.
- [x] `scripts/audit_artifacts.py`: **428/428 checks** — gồm kiểm tra chéo packet↔flow, re-encode toàn bộ edge, disjoint split, rebuild deterministic, protocol R, fixed population.
- [x] SHA256 toàn bộ raw OK.
- [x] `.gitignore` chặn pcap/graph/model; `reports/` được phép commit.

### 2.6 Bản đồ artifact

| Đường dẫn | Nội dung |
|---|---|
| `data/raw/` | 5 pcap + zip CSV + `SHA256SUMS` (không commit) |
| `data/processed/` | `packets_{day}.parquet`, `flows_{day}(_labeled).parquet`, `parse_summary_{day}.json` |
| `data/graphs/T/p{p}/` | `train1.npz`, `train2.npz`, `test.npz`, `summary.json` (p=2..8) |
| `data/graphs/R/p{p}/` | Protocol R cho p=2,4,8 |
| `data/graphs/T_fixed/p{p}/` | Fixed population (flow ≥8 gói) cho p=2..8 |
| `reports/qa_labeling_{day}.json` | QA nhãn |
| `reports/crosscheck_{day}.json` | Đối chiếu CSV |
| `reports/qa_labeling.md` | QA tổng hợp, sinh tự động |
| `reports/graph_stats.md` | Thống kê graph T/R/T_fixed |
| `reports/P1.md` | Báo cáo P1 sinh tự động từ CSV |
| `reports/ablation.md` | Bảng ablation sinh tự động từ `results/ablation.csv` |
| `results/A3_recon.csv` | Reconstruction-error ablation p=2,4,8 × 3 seed (Kaggle T4) |
| `src/` | 15 module pipeline |
| `tests/` | 11 file test |
| `scripts/audit_artifacts.py` | Audit tái chạy được |
| `scripts/make_qa_report.py` | Sinh QA markdown |
| `scripts/make_graph_stats.py` | Sinh graph stats |
| `scripts/make_p1_report.py` | Sinh `reports/P1.md` từ `results/P1_summary.csv` |
| `scripts/train_all.py` | Train 7 p × 3 seed, có resume |
| `configs/data.yaml` | Quyết định + tham số |
| `configs/cicids2017_schedule.yaml` | 18 cửa sổ tấn công |
| `requirements.txt` | Pin dependency Python 3.11 |
| `results/M1_summary.csv` | Bảng eval 126 dòng (21 model × 6 detector/ensemble) |
| `results/M1_p{p}_seed{s}.json` | Chi tiết TPR/FPR/AUROC/per-class |
| `results/P1_summary.csv` | P1 theo seed/alpha/method; có AUROC + TPR@FPR=1% |
| `results/P1_meta.json` | Calibration fraction, seeds, alphas, n_calib |
| `experiments/T/p{p}/seed{s}/` | Model + log (không commit) |
| `kaggle/`, `kaggle_long/` | Kernel metadata + script train GPU |

### 2.7 Kết quả tạm thời (checkpoint 2026-10-24)

GTAE + detector, protocol T, mean 3 seed, ensemble `tie`:

| p | TPR | FPR | AUROC |
|---|---:|---:|---:|
| 2 | 8,58% | 5,90% | 0,551 |
| 3 | 7,26% | 3,45% | 0,571 |
| 4 | 11,70% | 3,62% | 0,625 |
| 5 | 8,83% | 2,87% | 0,712 |
| 6 | 6,49% | 2,92% | 0,794 |
| 7 | 13,53% | 3,13% | 0,811 |
| 8 | 11,36% | 2,47% | 0,668 |

**Chẩn đoán:** RandomForest supervised trên **cùng edge features** (cùng ngày/phiên) đạt TPR **99,4%** ở FPR 6,1% (AUROC 0,972); nhưng **cross-day/open-class** (train Tue/Wed → test Thu/Fri) chỉ **18,1%** ở FPR 6,7% (AUROC 0,924). MLP-AE z=16/64/256, full-graph, subgraph 1.000 cạnh, K_max=64, bỏ LapPE đều không cải thiện (TPR 1–16%). Kết luận: features chỉ tách pattern cùng lớp/ngày; **one-class AE + detector chưa học được biên benign**; chưa tái hiện 99% của paper. Rà soát đầy đủ: [`REPRO_AUDIT.md`](REPRO_AUDIT.md).

**Baseline P1 (p=8, mean 3 seed):**

| Phương pháp | TPR | FPR | AUROC | TPR@FPR=1% |
|---|---:|---:|---:|---:|
| M1 GTAE ensemble tie | 11,36% | 2,47% | 0,668 | 9,64% |
| B0 raw vector ensemble tie | 0,50% | 1,22% | 0,698 | 2,13% |
| B1 MLP-AE ensemble tie | 6,29% | 2,29% | 0,595 | 6,95% |
| P1 Bonferroni α=0,05 | 16,92% | 3,43% | 0,656 | 0,00% |
| P1 Bonferroni α=0,10 | 23,47% | 6,18% | 0,656 | 0,00% |
| P1 Fisher α=0,05 | 47,67% | 17,73% | 0,646 | 6,07% |

**A3 reconstruction-error (p=8, mean 3 seed):** TPR **23,65%** @ FPR **4,17%**, AUROC **0,676**; p=2/4 yếu hơn M1. Chi tiết: [`reports/ablation.md`](../reports/ablation.md).

P1 dùng calibration 40% của `train2` (800 flow). Bonferroni α=0,05 kiểm soát FPR và tăng TPR so với M1 ở vùng FPR ~3–4%, nhưng **chưa vượt M1 tại FPR=1%**; Fisher có TPR cao nhưng FPR không kiểm soát. Chi tiết sinh tự động: [`reports/P1.md`](../reports/P1.md).

**Quyết định:** giữ kết quả trung thực; ưu tiên ablation/B2/A3 nếu còn thời gian; không tinh chỉnh để chạy đua con số paper.

---

## 3. Work plan còn lại

### Phase A — Chốt dữ liệu & nhãn (còn ~1 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| A1 | [x] Sinh `reports/qa_labeling.md` từ JSON | Markdown QA | Đủ bảng QA 5 ngày + giải thích ngưỡng | — | 0,5 |
| A2 | [x] Viết `tests/test_leakage.py` | Test | (i) không IP/port trong feature; (ii) split disjoint; (iii) train chỉ benign | — | 0,5 |
| A3 | [ ] Nhãn sửa Engelen eval-only | `src/corrected_labels.py` + report | Map được bằng 5-tuple; báo thêm cột “corrected”, **không train lại** | A1 | 1 |
| A4 | [x] Commit baseline code | Git commit | `pytest` xanh, data không bị track | — | 0,5 |

### Phase B — Đủ graph cho toàn bộ p & protocol R (xong)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| B1 | [x] Build p=3,5,6,7 (T) | `data/graphs/T/p{3,5,6,7}` | Đủ 7 p; audit pass | — | 0,5 |
| B2 | [x] Build protocol R | `data/graphs/R/...` | Cùng seed, flow disjoint, test có attack | B1 | 0,5 |
| B3 | [x] Fixed-population (flow ≥8 gói) | `data/graphs/T_fixed` | Cùng flow set cho mọi p | B1 | 0,5 |
| B4 | [x] Bảng thống kê graph theo p/class | `reports/graph_stats.md` | Khớp `summary.json` | B1 | 0,5 |

### Phase C — Train full trên Kaggle (2–3 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| C1 | [x] Đóng gói Kaggle Dataset (chia nhỏ do Kaggle treo file lớn) | `gtae-ids-*` datasets | Gồm graphs + code; 83 MB bị treo nên tách p2-p3/p4-p5/p7/p8 | B1 | 0,5 |
| C2 | [x] Script train + resume (notebook optional) | `scripts/train_all.py` | Chạy 1 lệnh cho 1 p; resume; lưu `model.pt`/log | C1 | 0,5 |
| C3 | [x] Chạy 7 p × 3 seed | 21 model | Val MSE 0,022–0,041; không NaN; GPU 10,6–18 s/run; p6 CPU | C2 | 1–2 |
| C4 | [x] Tải & verify kết quả | `experiments/T` + `runs.jsonl` | Checkpoint load lại được; 21/21 model | C3 | 0,5 |

**Runbook Kaggle (C1/C3):**

1. Tạo thư mục upload (không gồm pcap):
   ```
   kaggle_upload/
   ├── data/graphs/      # 89 MB
   ├── src/
   ├── configs/
   ├── scripts/
   └── pytest.ini
   ```
2. Tạo private Dataset `gtae-ids` (UI hoặc `kaggle datasets create -p kaggle_upload`).
3. Trong notebook: add dataset → copy vào `/kaggle/working` → chạy:
   ```bash
   python scripts/train_all.py --graphs data/graphs/T --out experiments/T \
     --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --epochs 100 --resume
   ```
4. `--resume` bỏ qua run đã có `model.pt`; session Kaggle bị ngắt thì chạy lại lệnh.
5. Save Version sau mỗi session; tải `experiments/` về local (21 × ~4 MB).

### Phase D — Embedding + detectors + eval (4–5 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| D1 | [x] `src/embed.py` | `.npy` train2/test | Encoder-only; shape `[N,d]`; deterministic | C3 | 1 |
| D2 | [x] `src/detectors.py` | IF/OCSVM/HBOS/INNE + vote | Fit chỉ train2; 2 luật vote; calibration 80/20 | D1 | 2 |
| D3 | [x] `src/eval.py` | Bảng metrics | TPR, FPR, Precision, F1, AUROC, PR-AUC, TPR@FPR=1% | D2 | 2 |
| D4 | [~] Chạy M0/M1 | `results/M1*.json/csv` | Đã chạy 21 model; TPR thấp hơn paper, xem §2.7 | D3 | 1 |
| D5 | [~] Per-class Table VII | `results/M1_*.json` | Đã có per-class; lớp <50 mẫu không kết luận | D4 | 1 |

### Phase E — Baseline & ablation (3–4 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| E1 | B0: vector 50p + detectors | `results/B0.csv` | Không đồ thị; p=2,4,8 | D2 | 1 |
| E2 | B1: MLP-AE | `results/B1.csv` | AE không đồ thị; 3 seed | D2 | 1 |
| E3 | B2: E-GraphSAGE-AE | `results/B2.csv` | Đồ thị không transformer | D2 | 1,5 |
| E4 | A1–A6 | `results/ablation.csv` | E-A3 xong (Kaggle T4); A2/B2/A5 còn | E1–E3 | 2 |
| E5 | Bảng “paper vs ours” | `reports/paper_vs_ours.md` | Có cột Δ + giải thích | E4 | 1 |

### Phase F — Proposal P1 (4–5 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| F1 | Conformal calibration | `src/calibrate.py` | FPR ≤ α trên calibration; báo FPR thực đo | D4 | 1,5 |
| F2 | Early exit theo p | `src/early_exit.py` | Dừng khi p-value ≤ α; lưu p_decision | F1 | 1,5 |
| F3 | Chạy P1 3 seed | `results/P1*.csv` | TPR@FPR cố định + số gói trung bình đến quyết định | F2 | 1,5 |
| F4 | [x] So sánh P1 vs M1 | `reports/P1.md` | Sinh tự động từ CSV; nêu drift và giới hạn calibration | F3 | 1 |

### Phase G — MAY (2–4 ngày, chỉ làm nếu còn thời gian)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| G1 | CIC-IDS2018 subset | `data/raw/2018/` | Đo dung lượng trước; có benign để tính FPR | C3 | 2–3 |
| G2 | Latency end-to-end | `results/latency.csv` | ms/flow + µs/packet + thời gian chờ p gói | D4 | 1 |
| G3 | Header hygiene (A5) | `results/hygiene.csv` | Bỏ TTL/2 checksum; so M1 | E4 | 1 |

### Phase H — Báo cáo & nộp (5–6 ngày)

| ID | Việc | Output | Acceptance | Dep | Est |
|---|---|---|---|---|---|
| H1 | [x] README 1 lệnh train + 1 lệnh eval | `README.md` | Đã thêm `PYTHONPATH=.`, `requirements.txt`, lệnh eval/P1 | D3 | 0,5 |
| H2 | Notebook/script Kaggle | `notebooks/` | Tái lập được kết quả | C3 | 0,5 |
| H3 | Báo cáo | `reports/report.pdf` | Đủ outline §8.1 | M5 | 4 |
| H4 | Slide 14 trang | `reports/slides.pdf` | Đúng §8.2 | H3 | 1 |
| H5 | Demo 5 phút | `demo/run_demo.sh` | Chạy offline trên pcap cắt | D3 | 1 |
| H6 | Q&A + tổng duyệt | checklist | Trả lời 12 câu §8.4 | H3–H5 | 1 |
| H7 | Commit/tag + AI disclosure | Git tag | Lịch sử sạch, ghi rõ công cụ AI theo quy định môn | all | 0,5 |

### Lịch dự kiến (tuần 6–12)

| Tuần | Việc chính | Milestone |
|---|---|---|
| 6 | Phase A + B (A1/A2/B1/B2 đã xong); Kaggle dataset | M2 hoàn chỉnh |
| 7 | Phase C: train full; bắt đầu D1 | M3 |
| 8 | Phase D: detectors + eval + per-class | M4 |
| 9 | Phase E: baseline + ablation | — |
| 10 | Phase F: P1; G nếu kịp | M5 |
| 11 | H1–H5: báo cáo, slide, demo | — |
| 12 | H6–H7: tổng duyệt, nộp, bảo vệ | M6 |

> Điều chỉnh theo deadline thực tế của môn. Thứ tự cắt khi thiếu thời gian: G → A3 → B3 → E2/E3 → giảm p curve còn 2,4,8.

### 3.10 Khi resume tái hiện (sau checkpoint)

1. **Feature standardization + loss weighting** cho vị trí khác 0 (zero-padding chiếm 50% vector).
2. **Bottleneck nhỏ hơn** (d=16/32) và **detector trên reconstruction error** (A3).
3. Chạy **protocol R đầy đủ** (7 p × 3 seed) và **nhãn corrected Engelen** để so sánh.
4. Nếu TPR vẫn thấp: chốt báo cáo **partial reproduction** + **supervised RF upper bound** (TPR 99,4% @ FPR 6,1%), ghi rõ paper không tái lập được dưới protocol sạch.

---

## 4. Rủi ro & hạn chế đã biết

| # | Rủi ro / hạn chế | Ảnh hưởng | Giảm thiểu |
|---|---|---|---|
| R1 | Heartbleed chỉ 1 flow; Infiltration 4–8; PortScan p=8 204 | Per-class TPR không đủ mẫu | Báo rõ; tập trung MUST classes; không claim per-class cho lớp <50 mẫu |
| R2 | Flow segmentation khác paper (paper 1.468/1.764 cạnh cho Heartbleed/Infiltration) | Không so trực tiếp Table VII | Ghi limitation; so xu hướng TPR–p |
| R3 | CSV CIC lỗi AM/PM + nhãn sai đã công bố | Đồng thuận <100% | Cross-check ±12h; báo confusion; tham chiếu Engelen |
| R4 | Kaggle giới hạn session/disk | Train dài bị ngắt | Checkpoint mỗi epoch; Save Version; chia run theo p |
| R5 | Siêu tham số paper không công bố (k, d, sampler, hòa phiếu) | Lệch kết quả | Ghi giả định; ablation k/K_max; báo cả 2 luật vote |
| R6 | Nhãn PortScan/Infiltration phụ thuộc quyết định schedule | Khó bảo vệ | Decision log §1 + QA report + tham chiếu trang CIC |
| R7 | Leakage kiểm tra mới ở mức synthetic + audit artifact | Khó phát hiện lỗi mới | `tests/test_leakage.py` + audit real artifact (428 checks) |
| R8 | Code chưa commit/tag đầy đủ | Mất lịch sử/khó chấm | A4 đã commit; H7 còn tag + AI disclosure |
| R9 | One-class AE + detector không tách attack (TPR 7–15% ở FPR 2–6%) | Không tái hiện 99% của paper | Đã thử full-graph/large-subgraph/K_max/PE/bottleneck; xem `REPRO_AUDIT.md`; chốt báo cáo partial + RF same-session/cross-day |

---

## 5. Definition of Done (cập nhật)

- [x] `test_fig3_vector` pass: đúng 25 byte, không chứa IP/port.
- [x] `encode_edge(p=3)` shape `(150,)`; p=8 `(400,)`.
- [x] Graph artifact có `day` + `flow_id`, tái lập deterministic.
- [x] GTAE val MSE giảm ≥50% so epoch 1 cho p=2…8 (p8: 0,105 → 0,041).
- [x] 21 model p2–p8 × 3 seed; checkpoint load lại được.
- [x] FPR từng detector trên benign held-out được đo.
- [~] TPR/FPR cho DoS Hulk + PortScan: đã đo per-class nhưng thấp; xem §2.7.
- [ ] README có đúng 1 lệnh train + 1 lệnh eval.
- [x] `tests/test_leakage.py` pass.
- [x] `reports/qa_labeling.md` sinh tự động.
- [x] 83 pytest + 428 audit checks pass.
- [x] Bảng “paper vs ours” + giải thích chênh lệch.
- [~] Ablation + P1 + 3 seed (P1 xong; ablation/B2 còn thiếu).
- [x] Báo cáo/slide/demo.

---

## 6. Lệnh tái chạy

```bash
# Test + audit + QA report
.venv/bin/python -m pytest -q
.venv/bin/python scripts/audit_artifacts.py
.venv/bin/python scripts/make_qa_report.py
sha256sum -c data/raw/SHA256SUMS

# Parse một ngày
.venv/bin/python -m src.parse_pcap \
  --pcap data/raw/Wednesday-workingHours.pcap \
  --out data/processed --day wednesday

# Label + QA + cross-check
.venv/bin/python -m src.label \
  --flows data/processed/flows_wednesday.parquet \
  --offset-minutes -180 \
  --csv data/raw/GeneratedLabelledFlows/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv \
  --out data/processed/flows_wednesday_labeled.parquet \
  --qa reports/qa_labeling_wednesday.json \
  --crosscheck reports/crosscheck_wednesday.json

# Build graph T cho p=2..8 và protocol R
.venv/bin/python -m src.build_dataset --p 2 3 4 5 6 7 8 --out data/graphs
.venv/bin/python -m src.build_dataset --split R --p 2 4 8 --out data/graphs

# Train một model (smoke/full)
.venv/bin/python -m src.train_gtae --p 8 --graphs data/graphs/T --out experiments/gtae_p8

# Train toàn bộ 7 p × 3 seed (Kaggle/local), có resume
.venv/bin/python scripts/train_all.py --graphs data/graphs/T --out experiments/T \
  --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --epochs 100 --resume
```

---

## 7. Việc còn chờ GVHD xác nhận

1. Scope MUST + SHOULD + MAY, bỏ ACI-IoT-2023.
2. Protocol **T** là kết quả chính, R chỉ để so paper.
3. Được dùng nhãn sửa Engelen cho eval phụ.
4. Định nghĩa “real-time”: báo cả µs/gói và ms/flow end-to-end.
5. P1 (calibrated fusion + early exit) đủ tiêu chí “cải tiến phương pháp” hay cần thay đổi kiến trúc.
6. Có cần gửi email xin siêu tham số còn thiếu từ tác giả không.

---

## 8. Quy ước cập nhật file này

- Mỗi task xong: đổi `[ ]` → `[x]`, ghi ngày + commit/artifact tương ứng.
- Thay đổi quyết định kỹ thuật: sửa bảng §1 và ghi lý do + bằng chứng.
- Kết quả thực nghiệm: chỉ điền số sau khi `scripts/audit_artifacts.py` và eval tái chạy được.
- Không xoá task đã cắt; chuyển sang mục “cắt do thời gian” kèm lý do.

