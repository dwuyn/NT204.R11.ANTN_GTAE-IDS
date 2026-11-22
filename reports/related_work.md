# So sánh với các bài báo liên quan - bảng có số và mức độ so sánh được

**Cập nhật:** 2026-11-22 (sửa lập luận về TPR ở §2.2/§2.4, đồng bộ §3 với kết quả 2018/ACI, thêm độ lệch chuẩn theo seed).
**Bài neo:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026-4041, 2025 → **[1]**.
**Nguồn số liệu:** cột `nguồn` của mỗi bảng ghi rõ một trong ba loại:

| nhãn | nghĩa |
|---|---|
| **[M]** | nhóm đo, đọc trực tiếp từ `results/*.csv` (tái chạy được bằng lệnh trong từng mục) |
| **[1]** | bảng trong bài neo - nguồn **thứ cấp**, bài gốc chưa đọc toàn văn |
| **[P]** | paper gốc (abstract/trích dẫn), **chưa** kiểm chứng lại |

Không có số nào trong tài liệu này được suy ra hay làm tròn từ ký ức; chỗ thiếu nguồn ghi **[THIẾU NGUỒN]**.

---

## 1. So sánh *cùng protocol* - nhóm tự cài và tự đo

Đây là phần duy nhất so sánh được trực tiếp: cùng dữ liệu (CIC-IDS2017, protocol `T` temporal), cùng 25-byte encoding, cùng 4 detector PyOD, cùng cách chia calibration (`train2`, 20% cho ngưỡng TPR@FPR=1%; P1 dùng 40%), cùng p. Mean ± std theo seed của mọi dòng: [`seed_stats.md`](seed_stats.md) - ví dụ AUROC M1 0,594 **± 0,106**, B2 0,689 **± 0,021**, A2 0,682 **± 0,003**, nên B2/A2 **ổn định hơn hẳn** (sd 0,021 và 0,003) và không bao giờ dưới 0,66, trong khi M1 trải 0,495-0,705; chênh lệch trung bình B2−M1 ≈ 0,096 nhưng sd của chênh lệch ghép cặp là 0,093 (n=3), nên **chưa thể nói "vượt phương sai seed"** - chỉ nói được B2/A2 ổn định hơn và không thua ở worst case; chênh lệch TPR ở ngưỡng riêng càng không đủ kết luận. Chạy lại:

```bash
python -m src.eval --models experiments/T --graphs data/graphs/T --out results --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --device cpu
python -m src.eval --models experiments/T_egsage --graphs data/graphs/T --out results/B2 --ps 2 4 8 --seeds 0 1 2 --device cpu
PYTHONPATH=. python scripts/eval_baselines_p1.py --calibration-fraction 0.4
```

| Phương pháp | Thay đổi so với GTAE-IDS | TPR | FPR | AUROC | TPR@FPR=1% | nguồn |
|---|---|---:|---:|---:|---:|---|
| **M1 GTAE p8** (baseline của nhóm) | - | 4,18% | 2,79% | 0,594 | 3,65% | [M] `results/M1_summary.csv` |
| A2 - bỏ LapPE | bỏ positional encoding | 6,36% | 1,23% | 0,682 | 12,46% | [M] `results/noPE/` |
| A3 - reconstruction-error | bỏ 4 detector, dùng MSE tái tạo | 6,01% | 2,07% | 0,649 | 6,01% | [M] `results/A3_recon.csv` |
| A5 - header hygiene | zero TTL + 2 checksum rồi train lại | 2,83% | 2,33% | 0,675 | 3,77% | [M] `results/A5_hygiene.csv` |
| **B0 - raw vector** (không đồ thị) | bỏ encoder, đưa thẳng 50p chiều cho detector | 0,50% | 1,22% | **0,698** | 2,13% | [M] `results/B0_summary.csv` |
| B0 + HBOS (đơn detector) | như trên, chỉ HBOS | 0,00% | 1,66% | **0,810** | 0,00% | [M] `results/B0_summary.csv` |
| B1 - MLP-AE | học biểu diễn không dùng đồ thị | 6,29% | 2,29% | 0,595 | 6,95% | [M] `results/B1_summary.csv` |
| **B2 - E-GraphSAGE-AE** ([6] cùng họ) | mean aggregation, cùng độ sâu/độ rộng | **9,78%** | 1,81% | **0,689** | 11,30% | [M] `results/B2/M1_summary.csv` |
| P1 - conformal + early-exit | tầng quyết định, α = 0,10 Bonferroni | 14,11% | 5,78% | 0,66 | 0,00% | [M] `results/P1_summary.csv` |

Đọc bảng này: **hai kết luận định lượng** mà bảng so sánh của paper không có -

1. **Attention không phải thứ tạo ra tín hiệu.** B2 cùng độ sâu/độ rộng nhưng thay attention bằng mean: p2 0,504 vs 0,505 · p4 0,653 vs 0,578 · **p8 0,689 vs 0,594**. Không có p nào attention thắng rõ.
2. **Đồ thị không phải thứ tạo ra tín hiệu xếp hạng.** B0 (không đồ thị, chỉ vector header thô) đạt AUROC **0,698** với ensemble và **0,810** với HBOS - cao hơn M1 (0,594). Nghĩa là trong protocol này, phần "graph transformer" đang *làm mất* tín hiệu so với chính đầu vào thô của nó.

---

## 2. So với số công bố - cùng bảng, khác điều kiện

### 2.1 Per-class (paper Table VII) - đây là chỗ khoảng cách lộ rõ nhất

Điều kiện của paper: test set dựng lại từ Table VII, cấu hình chọn theo grid contamination, ensemble. Của nhóm: cùng quy trình trên `data/graphs/P_paper` (`results/paper_parity/`).

| Attack | paper [1] Table VII | nhóm, `P_paper` [M] | n của nhóm |
|---|---:|---:|---:|
| DoS GoldenEye | 99,08% | **0,75%** | 6.090 |
| Heartbleed | 99,52% | **0,00%** | 11 |
| DoS Slowhttptest | 99,79% | **0,76%** | 964 |
| DoS Slowloris | 99,60% | **2,00%** | 1.002 |
| DoS Hulk | 98,74% | **0,58%** | 5.000 |
| PortScan | 98,50% | **25,31%** | 6.451 |
| DDoS | 99,34% | **0,61%** | 5.000 |
| Infiltration | 99,83% | **0,98%** | 34 |
| Web Attack - Brute Force | 99,29% | **0,48%** | 140 |
| SSH-Patator | 98,86% | **0,19%** | 175 |
| FTP-Patator | 98,85% | **1,72%** | 174 |

Không lớp nào đạt 1/3 con số paper. PortScan là lớp "dễ" nhất của nhóm (25,31%) và cũng là lớp paper ghi 98,50%.

### 2.2 So với các baseline mà chính paper [1] dẫn ra

**Table XI của [1]** - GNN supervised *flow-based*, CIC-IDS2017, chia cân bằng benign/attack (TPR theo lớp, [1] báo):

| Method | Slowloris | Hulk | GoldenEye | Heartbleed | WebBF | DDoS |
|---|---:|---:|---:|---:|---:|---:|
| E-GraphSAGE [6] | 0,973 | 0,989 | 0,992 | 0,983 | 0,954 | 0,965 |
| E-ResGAT / GNN [7,9] | 0,982 | 0,993 | 0,991 | 0,978 | **0,734** | 0,991 |
| GraphDDoS | 0,967 | 0,993 | 0,978 | 0,981 | 0,967 | 0,983 |
| GTAE-IDS [1] | 0,996 | 0,988 | 0,991 | 0,996 | 0,993 | 0,994 |

> **Đã đối chiếu PDF gốc** (`docs/related/`, chi tiết: [`related_work_verification.md`](related_work_verification.md)):
> dòng **E-GraphSAGE** ở bảng này **không có trong bài gốc** (bài gốc đánh giá NF-UNSW-NB15 / NF-ToN-IoT / NF-BoT-IoT, metric F1/FAR, không có CIC-IDS2017 hay TPR từng lớp) - số của [1] là tính lại/không dẫn nguồn, không nên trích như số của E-GraphSAGE; dòng **Pujol-Perich** khớp Bảng 1 của bài gốc (accuracy từng lớp, bỏ 90% benign) nhưng bài gốc **không có** Heartbleed/Infiltration; dòng GraphDDoS và PBCNN/SPIN-IDS vẫn là nguồn thứ cấp (paywall).

**Table XII của [1]** - packet-based không đồ thị, CIC-IDS2017 (TPR / µs mỗi gói):

| Method | TPR | µs/gói |
|---|---:|---:|
| PL-RNN | 0,564 | 2,91 |
| Packet2Vec | 0,728 | 3,54 |
| HAST-II | 0,690 | 4,2 |
| AEIDS | 0,587 | 2,65 |
| PayloadEmbeddings | 0,954 | 2,73 |
| PBCNN [4] | 0,983 | 7,89 |
| **GTAE-IDS [1]** | 0,990 | **1,28** |

**Table XIII của [1]** - so với SPIN-IDS [2], TPR theo p (%):

| p | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|
| SPIN-IDS (supervised, có payload) | 81,59 | 86,50 | 92,02 | 94,47 | 97,54 | 97,54 | 98,77 |
| GTAE-IDS | 84,47 | 91,02 | 94,72 | 97,16 | 98,44 | 98,72 | 99,04 |
| **nhóm, `T` [M]** | **3,30** | 4,18 | 8,56 | 6,31 | 14,93 | 6,90 | 4,18 |

**Table XIV/XV của [1]** - thời gian: GTAE-IDS train 5,43 h, suy luận **1,28 µs/gói**; E-GraphSAGE 3,1 h / 1,2 µs; GNN-based 2,7 h / 1,45 µs; GraphDDoS 4,6 h / 2,12 µs. Chính [1] ghi chú: baseline **không tính** thời gian trích đặc trưng flow và thời gian chờ luồng kết thúc.

### 2.3 Các paper khác đọc được số (không cùng điều kiện)

| Paper | Số công bố | Điều kiện | So được với nhóm? |
|---|---|---|---|
| Anomal-E [8] / [P] | HBOS trên CSE-CIC-IDS2018: macro-F1 **86,28 → 94,51** khi dùng embedding thay đặc trưng thô (**đã kiểm chứng**, Bảng 5 của bài gốc) | NetFlow, self-supervised, contamination 0% | Không cùng metric (macro-F1 vs TPR/AUROC) và không cùng định nghĩa flow |
| GraphIDS [10] / [P] | PR-AUC tới **99,98%**, macro-F1 tới **99,61%** | NetFlow benchmarks, self-supervised | Không; nhưng cùng *kiểu* claim zero-day → đối chiếu §3.4 |
| Kitsune [11] / [P] | TPR/FPR/AUC trên mạng camera IoT tự dựng | packet-streaming, unsupervised | **[THIẾU NGUỒN]** - số cụ thể chưa trích; cần đọc toàn văn nếu đưa vào báo cáo |
| nPrint [5] / [P] | không có số TPR trong nguồn đã đọc | - | Chỉ so định tính (căn chỉnh theo trường) |

**Điều kiện khác nhau ở đâu** (phải nói rõ khi trình bày, nếu không là so khập khiễng):
paper [1] và các baseline của nó dùng **chia cân bằng benign/attack** (5.000 benign + 5.000 attack theo lớp) và **có nhãn tấn công** trong Table XI; nhóm dùng **temporal, one-class, benign-only training**, test là toàn bộ lưu lượng Thứ Ba-Thứ Sáu (30.907 edge, 84% attack).

**Lưu ý khi diễn giải khoảng cách TPR:** với ngưỡng cố định (đặt trên benign `train2`), TPR chỉ tính trên các mẫu tấn công nên **không phụ thuộc tỉ lệ benign/attack** - tỉ lệ này chỉ ảnh hưởng precision. Vì vậy "cân bằng vs mất cân bằng" **không** giải thích được TPR rơi từ ~0,99 xuống vài phần trăm. Các khác biệt thật sự là: (i) có nhãn hay không (Table XI là supervised), (ii) benign test cùng ngày hay khác ngày với train, và (iii) với mô hình đồ thị, **thành phần đồ thị test** - đồ thị chỉ gồm một lớp tấn công (như code tác giả, `docs/REPRO_AUDIT.md` F3) có topo khác hẳn đồ thị trộn benign, nên embedding của cùng một luồng tấn công thay đổi theo đồ thị nó nằm trong.

---

### 2.4 Đo của nhóm trên chính hai bộ chuyển miền (bổ sung mà paper không có)

Paper chỉ báo TPR trên 2018/ACI vì test của họ **chỉ có lưu lượng độc hại**. Nhóm đo lại
trên cùng hai bộ nhưng có benign để tính FPR - cùng 25-byte, cùng 4 detector, cùng p=8:

| bộ | test | paper TPR | nhóm TPR | nhóm FPR | nhóm AUROC | nhóm TPR@1% |
|---|---|---:|---:|---:|---:|---:|
| CIC-IDS2018 (1 ngày) | 5.000 benign (5 host) + 5.000 Hulk | 98,74% | 5,99% | 1,52% | 0,764 | 5,94% |
| ACI-IoT-2023 | 5.000 benign **ngày khác** + 15.000 tấn công (3 lớp) | 98,21% | 1,69% | 1,11% | 0,536 | 1,95% |

Hai con số paper là "TPR trên đồ thị test chỉ gồm tấn công"; hai con số của nhóm là TPR khi
đồ thị test trộn benign thật và ngưỡng được đặt trên benign train. Bản thân việc đo thêm FPR
**không** làm TPR thay đổi (TPR chỉ tính trên mẫu tấn công). Khoảng cách 98,74 → 5,99 (2018)
và 98,21 → 1,69 (ACI) đến từ chất lượng embedding (AUROC 0,764 và 0,536) và từ thành phần đồ
thị test (chỉ-tấn-công vs trộn benign, xem §2.2), không phải lỗi cài đặt.

## 3. Bốn tuyên bố của paper, đối chiếu bằng số đo của nhóm

| Tuyên bố của [1] | Đo được | Kết luận |
|---|---|---|
| **Attention cạnh-cạnh (graph transformer) là cần thiết** | B2 mean-aggregation ≥ M1 ở p4 và p8 (0,653 vs 0,578; **0,689 vs 0,594**) | **Không xác nhận.** Toán tử attention không phải nguồn tách biệt; [1] không có ablation này |
| **Byte checksum/TTL không phải shortcut** (hàm ý từ việc cắt 25 byte) | A5 zero 5/25 byte rồi train lại: AUROC 0,594 → **0,675**, cả IForest/OCSVM/INNE đều tăng | **Xác nhận**, và mạnh hơn: bỏ các byte phụ thuộc địa chỉ *không* làm mất khả năng phân biệt |
| **Ngữ cảnh đồ thị giúp phát hiện** | B0 (không đồ thị) AUROC 0,698 / HBOS 0,810 > M1 0,594 | **Không xác nhận** trong protocol này. Đồ thị chưa chứng minh được lợi ích xếp hạng |
| **"Real-time": 1,28 µs/gói** | end-to-end thật trên replay Thứ Sáu: **15.272 µs/gói** (forward-only 1.663 µs/gói); 8,2 flow/s vs 12,1 flow/s lưu lượng đến | **Không xác nhận ở mức triển khai.** Con số 1,28 µs là model-only trên GPU và *không* tính trích đặc trưng + chờ luồng - đúng phần chiếm phần lớn thời gian |

Hai tuyên bố nữa của [1], đối chiếu bằng số đo:
- **Tổng quát hoá sang môi trường mới** (Table VIII/IX của [1], TPR > 98%): nhóm đo trên một ngày CIC-IDS2018 và ACI-IoT-2023 có benign trong test (§2.4): TPR 5,99% / 1,69%, AUROC 0,764 / 0,536 → **không xác nhận**. Giới hạn: 2018 mới có 1 ngày (Hulk), ACI 3 lớp tấn công (`reports/cross_dataset.md`).
- **Thiết lập benign train/test**: [1] chỉ nói dữ liệu được coi là *"snapshot at an arbitrary timestamp t"* (§IV-B), không nêu ngày. Code của tác giả dùng Friday 70/30 cho cả train và benign test (`docs/REPRO_AUDIT.md` F4). Đây là lý do nhóm chọn protocol `T` (train Monday, test Tue-Fri) làm chính - một lựa chọn của nhóm để đo dưới dịch chuyển thời gian, không phải thiết lập paper công bố.

---

## 4. Ưu/nhược có bằng chứng (thay cho nhận xét cảm tính)

**Ưu điểm của GTAE-IDS mà nhóm xác nhận được**

| Điểm | Bằng chứng |
|---|---|
| Kiến trúc cạnh (edge-level) + line graph là cài đặt được, không cần PyG | `src/model_gtae.py`, `src/line_graph.py`; 132 test pass |
| Không cần nhãn tấn công để học biểu diễn | train chỉ dùng Monday benign; eval trên Thứ Ba-Thứ Sáu |
| Pipeline 25 byte/gói chạy được ở p = 2..8 | 21 checkpoint, `results/M1_summary.csv` |
| Phát hiện sớm *có* ý nghĩa về chi phí | P1: APD 7,56 gói, 13,22% attack quyết định trước gói 8 |

**Nhược điểm nhóm phát hiện thêm (ngoài 4 lỗi forensic trong `REPRO_AUDIT.md`)**

| Điểm | Bằng chứng |
|---|---|
| Attention không cần thiết; mean-aggregation tương đương hoặc tốt hơn | B2 vs M1 (§1) |
| Đồ thị chưa chứng minh được lợi ích so với vector thô | B0 0,698 / HBOS 0,810 > M1 0,594 |
| "Real-time" không đúng ở mức triển khai: 8,2 < 12,1 flow/s | `reports/latency.md` |
| Nút = (IP, port) làm đồ thị phân mảnh; nút = IP (như Anomal-E [8]) chưa được thử | đề xuất P4 trong `docs/GTAE-IDS_Research_docs.md` §6, chưa cài |
| Tái tạo toàn bộ bằng MSE cho phép mô hình "copy" đặc trưng cạnh | đề xuất P5 (GraphMAE-style), chưa cài |

---

## 5. Nếu cần so *công bằng* hơn nữa - ba lựa chọn, theo chi phí

| Lựa chọn | Trả lời được câu gì | Chi phí |
|---|---|---|
| **(a) Đã xong:** bảng §1 + §2 với cột "khác điều kiện" | "Nhóm có biết các bài khác làm gì và khác ở đâu" | 0 |
| **(b)** Chạy **supervised** E-GraphSAGE (B2 + classifier) trên split cân bằng như Table XI của [1] | Tách *supervision* khỏi *biểu diễn*: nếu có nhãn thì 0,99 có tái lập không? | ~1 ngày (dùng lại B2 encoder, thêm đầu phân loại) |
| **(c)** Cài **Anomal-E** (DGI 1 lớp trên E-GraphSAGE - chính là encoder B2) và **Kitsune** (AfterImage) trên protocol `T` | So sánh *định lượng* với 2 họ gần nhất (self-supervised GNN, online packet-level) | ~2 ngày (Anomal-E) + ~1 ngày (Kitsune) |

Khuyến nghị: (a) đã đủ cho tiêu chí "phân tích, so sánh, đánh giá ưu/nhược"; (b) là lựa chọn đáng làm nhất nếu còn thời gian, vì nó trả lời đúng câu hỏi mà mọi bảng so sánh của paper né tránh - *bao nhiêu phần trăm khoảng cách là do không có nhãn, bao nhiêu là do biểu diễn*.

---

## 6. Giới hạn của chính tài liệu này

- Số của [1] là **nguồn thứ cấp**: đọc từ bảng trong bài neo, chưa mở lại bài gốc của E-GraphSAGE / PBCNN / Anomal-E / Kitsune.
- Không có bảng nào ở đây so *cùng dataset, cùng metric, cùng split* với paper khác - vì không paper nào trong nhóm này công bố trên protocol temporal one-class của nhóm. Đó là lý do §1 (so trong nội bộ) là bảng có giá trị nhất.
- Các số [M] đều tái chạy được từ `results/*.csv` + lệnh ở §1; `scripts/audit_artifacts.py` kiểm 428 ràng buộc trên artefact thô.
