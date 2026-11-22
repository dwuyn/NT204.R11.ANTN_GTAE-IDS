# BÁO CÁO NGHIÊN CỨU ĐỒ ÁN MÔN HỌC
## HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG THỜI GIAN THỰC DỰA TRÊN ĐỒ THỊ BIẾN ĐỔI TỰ MÃ HÓA (GTAE-IDS)
### TÁI HIỆN ĐỘC LẬP, ĐỐI CHIẾU MÃ NGUỒN GỐC, SO SÁNH VỚI CÁC NGHIÊN CỨU LIÊN QUAN VÀ ĐỀ XUẤT CẢI TIẾN

---

**Môn học:** Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập (NT204.R11.ANTN)
**Bài báo nghiên cứu cơ sở (paper neo):**
> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026–4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

**Cấu trúc báo cáo theo yêu cầu đề tài:**

| Yêu cầu | Chương |
|---|---|
| Tìm hiểu vấn đề và phương pháp trong bài báo | Chương 1, 2 |
| Thực hiện lại phương pháp và đánh giá kết quả | Chương 3, 4 |
| Phân tích, so sánh, đánh giá ưu/nhược so với bài báo liên quan | Chương 5 (đối chiếu mã nguồn gốc), Chương 6 (so sánh với các bài liên quan) |
| Đề xuất giải pháp cải thiện | Chương 7 |

---

## TÓM TẮT

Đồ án tái hiện độc lập **GTAE-IDS** (IEEE TIFS 2025). Đây là framework học **không giám sát** trên đồ thị luồng mạng, chỉ dùng **p gói đầu** của mỗi luồng để phát hiện tấn công sớm. Nhóm xây dựng lại toàn bộ pipeline từ 51 GB pcap thô của CIC-IDS2017, huấn luyện 21 mô hình canonical (p = 2..8 × 3 seed) + 28 mô hình bổ sung (4 seed × 7 p) cho kiểm tra độ bất định, viết 132 kiểm thử tự động và 428 phép kiểm tra chéo trên artefact.

**Kết quả tái hiện:** con số công bố **TPR 99,04% @ FPR 6,56%** không tái lập được.
- Protocol `T` (train benign Monday, test Tue–Fri) đạt TPR **4,18 ± 4,30%** @ FPR **2,79 ± 1,40%**, AUROC **0,594 ± 0,106** (3 seed).
- Protocol `P_paper` dựng lại đúng thành phần test của Table II/VII và đúng luật OR trong code tác giả, nhưng vẫn chỉ đạt **3,25%** TPR tại cùng FPR 6,56%.

**Đối chiếu bài báo với mã nguồn công khai** (Chương 5). Nhóm kiểm chứng được:
- Table VII trùng khớp từng số với luật **OR** (`votes >= 1`), trong khi bài báo mô tả *majority voting*.
- FPR Ensemble công bố (6,56%) không khớp CSV công khai của tác giả (13,12%).
- Mỗi lớp tấn công được test trên **một đồ thị riêng**, benign train/test cùng **một ngày**.
- Detector chạy trên **output của decoder**, và notebook công bố **không chạy được** như hiện có.

**So sánh với nghiên cứu liên quan** (Chương 6). Các baseline cùng protocol cho thấy:
- **Attention không phải nguồn tín hiệu**: E-GraphSAGE-AE (mean aggregation) đạt AUROC **0,689 ± 0,021**, cao hơn GTAE.
- **Ngữ cảnh đồ thị chưa giúp ích**: vector header thô (B0) đạt AUROC **0,698**.
- **"Real-time" không đạt ở mức triển khai**: 8,2 flow/s, trong khi lưu lượng đến là 12,1 flow/s.

**Đề xuất cải tiến** (Chương 7) gồm hai tầng:
- **(A) Tầng biểu diễn:** thay attention bằng mean aggregation và bỏ LapPE. Đã đo: AUROC tăng từ 0,594 lên 0,68–0,69, độ lệch chuẩn giữa các seed giảm 5–38 lần, TPR@FPR=1% tăng từ 3,65% lên 11–12%.
- **(B) Tầng quyết định (P1):** conformal p-value kết hợp early-exit tuần tự theo p. Bonferroni giữ được FPR thực đo ≤ α (3,64% @ α=0,05; 5,78% @ α=0,10), nhưng TPR tăng ít và tại FPR=1% không vượt M1.

Nhóm trình bày cả những tiêu chí **không đạt**: đường cong TPR theo p không đơn điệu, GTAE không vượt baseline không dùng đồ thị.

---

## CHƯƠNG 1: GIỚI THIỆU VÀ ĐỘNG CƠ NGHIÊN CỨU

### 1.1 Bài toán phát hiện xâm nhập mạng (NIDS)
- **NIDS dựa trên luật (signature-based)** như Snort/Suricata: chính xác với tấn công đã biết nhưng bất lực trước tấn công zero-day.
- **NIDS dựa trên thống kê luồng (flow-based)**: dùng CICFlowMeter trích 80+ đặc trưng thống kê. Điểm yếu là **độ trễ**: phải chờ luồng kết thúc hoặc hết timeout (120 s) mới có đặc trưng, nên không thể chặn tấn công ngay trên đường truyền (in-line).
- **NIDS học có giám sát (supervised)**: cần nhãn tấn công, và chủ yếu nhận ra các tấn công giống với dữ liệu huấn luyện.

### 1.2 Động cơ của GTAE-IDS
Bài báo đặt ra ba mục tiêu (§I, tr. 4026–4027):
1. **Phát hiện sớm:** chỉ dùng p gói đầu (p = 2..8) của mỗi luồng, quyết định ngay khi luồng vừa bắt đầu.
2. **Không cần nhãn tấn công:** học phân phối benign bằng autoencoder trên đồ thị, phát hiện bất thường bằng detector không giám sát.
3. **Tận dụng ngữ cảnh giữa các luồng:** biểu diễn lưu lượng dưới dạng đồ thị, dùng graph transformer để mỗi luồng "nhìn thấy" các luồng chung đầu mút.

### 1.3 Câu hỏi nghiên cứu của đồ án
- **RQ1:** Phương pháp có tái lập được từ mô tả của bài báo không? Nếu không, khoảng cách đến từ đâu?
- **RQ2:** Từng thành phần (đồ thị, attention, LapPE, ensemble) đóng góp bao nhiêu so với các phương pháp liên quan?
- **RQ3:** Có thể cải thiện ở tầng biểu diễn hoặc tầng quyết định không, và với chi phí nào?

---

## CHƯƠNG 2: PHƯƠNG PHÁP CỦA BÀI BÁO

### 2.1 Biểu diễn gói tin và đồ thị
- **Đặc trưng gói tin (Fig. 3):** mỗi gói TCP/IPv4 giữ **9 byte IP header** (bỏ version, IHL, ToS, protocol, địa chỉ IP) và **16 byte TCP header** (bỏ port, options). Tổng 25 byte, chia cho 255.
- **Hướng truyền (Fig. 4):** mỗi gói là vector 50 chiều. Gói chiều đi (fwd) đặt 25 byte ở nửa đầu, nửa sau là 0; gói chiều về (bwd) ngược lại. p gói cho vector 50p chiều (p = 8 → 400 chiều).
- **Đồ thị:** nút u = (IP, port), không có đặc trưng nút; mỗi luồng là một cạnh vô hướng mang vector 50p chiều. Bài báo coi dữ liệu nhiều ngày như **"một snapshot tại thời điểm t bất kỳ"** (§IV-B, tr. 4034).

### 2.2 Bộ mã hoá graph transformer trên cạnh (GTAE)
- Attention tính giữa các cạnh **chung đầu mút**, tức là trên **line graph** L(G), theo eq. (4)–(8):
  $$\text{Attn}(e_i, e_j) = \text{Softmax}\left(\frac{(e_i W_Q)(e_j W_K)^T}{\sqrt{d}}\right)(e_j W_V), \quad e_j \in \mathcal{N}_{\mathcal{L}(G)}(e_i)$$
- **Laplacian Positional Encoding (LapPE):** vector riêng của Laplacian chuẩn hoá, cộng vào đặc trưng cạnh.
- **Decoder:** mạng DNN tái tạo lại vector 50p chiều, hàm mất mát MSE. Kiến trúc thay đổi theo p (Table III: p = 8 dùng 6 lớp, 8 head, bottleneck d = 64).

### 2.3 Phát hiện bất thường và bầu chọn
Encoder sau khi huấn luyện trên `train 1` (benign) được dùng để sinh **embedding ở bottleneck** cho `train 2` (benign, không trùng `train 1`). Bốn detector được fit trên các embedding này:
1. **OCSVM** (One-Class SVM, kernel rbf): tìm siêu phẳng bao lấy dữ liệu benign.
2. **IForest** (Isolation Forest, 150 cây): cô lập điểm bất thường bằng các cây phân chia ngẫu nhiên.
3. **HBOS** (Histogram-Based Outlier Score, 20 bin): ước lượng mật độ độc lập theo từng chiều bằng histogram.
4. **INNE** (*Isolation using Nearest-Neighbor Ensembles*, 100 estimator): cô lập điểm bằng các siêu cầu dựng quanh mẫu con, bán kính là khoảng cách đến láng giềng gần nhất.

Bài báo mô tả luật kết hợp là **majority voting** (§III-B, tr. 4033). Contamination được chọn bằng grid `{0,001; 0,01; 0,04; 0,05; 0,1}` (Table V).

### 2.4 Kết quả công bố
- Table VI, p = 8: Ensemble **TPR 99,04% / FPR 6,56%**; các detector đơn có FPR 4,03–4,99%.
- Table VII: TPR theo từng lớp tấn công đều > 98,5%.
- Table VIII: TPR > 98% trên CIC-IDS2018 và ACI-IoT-2023. Lưu ý: các tập test này **chỉ có lưu lượng tấn công**, nên không đo được FPR.
- Table XII: thời gian suy luận **1,28 µs/gói**.

### 2.5 Những điểm bài báo không mô tả rõ
Đây là các điểm ảnh hưởng trực tiếp tới khả năng tái lập. Nhóm phải tự giả định (xem `docs/REPRO_AUDIT.md` §1):

| Điểm chưa rõ | Hệ quả | Lựa chọn của nhóm |
|---|---|---|
| Benign train/test lấy từ ngày nào | Không biết có dịch chuyển phân phối giữa train và test không | Protocol `T` (Monday → Tue–Fri) làm chính; `P_paper` (Friday) để đối chứng |
| Đồ thị test trộn benign + attack hay tách riêng từng lớp | Topo của đồ thị chỉ có attack có thể tự "lộ" nhãn | Trộn chung (đúng tình huống triển khai) |
| Chiều LapPE, kích thước subgraph khi train, K_max | Ảnh hưởng tới huấn luyện | k = 8, ≤ 200 cạnh, K_max = 32 |
| Luật hoà phiếu 2–2 | Định nghĩa "majority" với 4 detector | Báo cả `strict` (≥ 3/4) và `tie` (≥ 2/4) |
| "1,28 µs/gói" đo những công đoạn nào | Không biết claim "real-time" bao gồm những gì | Đo end-to-end trên replay pcap (Chương 4.5) |

---

## CHƯƠNG 3: TÁI HIỆN PHƯƠNG PHÁP

### 3.1 Pipeline
Toàn bộ pipeline viết bằng Python/PyTorch thuần (không dùng PyG):

| Bước | Module | Ghi chú |
|---|---|---|
| Đọc pcap, tách luồng | `src/parse_pcap.py` | Streaming; 5-tuple; kết thúc luồng khi idle > 120 s hoặc gặp SYN mới sau FIN/RST |
| Gán nhãn | `src/label.py` | Lịch tấn công CIC + đối chiếu với CSV CICFlowMeter; gắn nhãn `UNCERTAIN` khi không chắc |
| Mã hoá 25 byte | `src/packet_encoder.py` | Kiểm chứng bằng test vector theo Fig. 3 |
| Dựng đồ thị, line graph, LapPE | `src/graph_builder.py`, `src/line_graph.py`, `src/pe.py` | LapPE dùng vector khởi tạo ARPACK có seed |
| Mô hình | `src/model_gtae.py` | `ARCH` khớp Table III cho p = 2..8 |
| Huấn luyện | `src/train_gtae.py` | Adam, lr 1e-3, 100 epoch, 50 subgraph/batch |
| Detector, đánh giá | `src/detectors.py`, `src/eval.py` | Đúng siêu tham số Table V |

Các protocol đánh giá:
- **`T` (chính):** train1/train2 lấy benign Monday; test lấy Tue–Fri (5.000 benign + tối đa 5.000 flow mỗi lớp tấn công).
- **`T_fixed`:** cùng một quần thể 30.907 flow có ≥ 8 gói cho mọi p, để so sánh công bằng giữa các p.
- **`R`:** chia ngẫu nhiên theo flow, gần với cách hiểu "snapshot" của bài báo.
- **`P_paper`:** dựng theo dòng CSV CICFlowMeter, đúng số lượng từng lớp như Table VII, đúng grid contamination, đúng luật OR của code (Chương 4.3).

**Quy trình huấn luyện:** 21 mô hình canonical (7 giá trị p × 3 seed) + 28 mô hình bổ sung (4 seed × 7 p, `experiments/T_probe`) để đo độ bất định; lần đầu chạy trên Kaggle T4, bản cuối được huấn luyện lại từ đầu trên CPU ngày 2026-11-16.

### 3.2 Kiểm thử và chống rò rỉ dữ liệu
- **132 test `pytest` pass**: không có IP/port trong đặc trưng, các split rời nhau, train chỉ có benign, test cho conformal/early-exit, test cho script thống kê seed.
- `scripts/audit_artifacts.py`: **428/428** phép kiểm tra chéo trên artefact thật (khoá ngoại packet ↔ flow, mã hoá lại, nhãn, split, dựng lại đồ thị tất định).

---

## CHƯƠNG 4: KẾT QUẢ TÁI HIỆN VÀ ĐÁNH GIÁ

### 4.1 Kết quả chính (p = 8, protocol `T`, mean ± std 3 seed)

| Phương pháp | TPR | FPR | AUROC [min–max] |
|---|---:|---:|---:|
| **Paper Table VI** (Ensemble) | 99,04% | 6,56% | — |
| **M1: GTAE tái hiện** (ensemble tie) | **4,18 ± 4,30%** | **2,79 ± 1,40%** | **0,594 ± 0,106** [0,495–0,705] |
| M1, chỉ INNE | 8,69 ± 12,30% | 1,84 ± 1,37% | 0,578 ± 0,116 |

**Phương sai giữa các seed rất lớn:** AUROC của 3 seed là 0,705 / 0,581 / 0,495; seed kém nhất gần như đoán ngẫu nhiên. Vì vậy với 3 seed, mọi chênh lệch nhỏ hơn khoảng 1 std **không** đủ để kết luận. Tuy nhiên, khoảng cách tới con số 99% của bài báo lớn hơn hàng chục lần độ lệch chuẩn, nên kết luận "không tái lập được" vẫn đứng vững.

### 4.2 Đường cong theo p (ensemble tie; 7 seed mỗi p)

| p | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|
| TPR (%) | 2,99 ± 1,66 | 7,31 ± 4,35 | 9,29 ± 5,83 | 8,82 ± 8,74 | 9,21 ± 8,93 | 4,43 ± 7,46 | 7,63 ± 6,56 |
| AUROC | 0,499 ± 0,022 | 0,494 ± 0,024 | 0,597 ± 0,044 | 0,680 ± 0,020 | **0,774 ± 0,068** | 0,709 ± 0,157 | 0,663 ± 0,092 |
| AUROC min–max | 0,470–0,529 | 0,468–0,525 | 0,542–0,681 | 0,650–0,715 | 0,698–0,886 | 0,460–0,843 | 0,495–0,750 |

Bảy seed mỗi p (3 canonical + 4 bổ sung, `results/probe_extra_seeds/`). So với 3 seed, p=8 tăng từ 0,594 lên **0,663 ± 0,092** — cú rơi ở p=8 một phần là nhiễu seed. Nhưng đường cong vẫn **không đơn điệu**: AUROC đỉnh ở p=6 rồi giảm ở p=7–8, TPR cũng vậy. Tiêu chí "TPR tăng theo p" vì thế **không đạt ngay cả với 7 seed** — đây là kết quả đo, không phải thiếu mẫu. Khoảng cách tới 99,04% của bài báo vẫn lớn hơn nhiều lần độ lệch chuẩn.

### 4.3 Dựng lại đúng thiết lập của bài báo (`P_paper`)
Để loại trừ khả năng "kết quả âm chỉ là do cách dựng tập test của nhóm", nhóm dựng protocol `P_paper`:
- lấy **dòng CSV CICFlowMeter làm định nghĩa luồng** (đúng cách bài báo đếm cạnh);
- chọn đúng số lượng từng lớp theo Table VII; **zero-pad** các luồng ngắn thay vì loại bỏ (`src/cic_graph.py`);
- benign lấy từ Friday, như code của tác giả.

| Tập test (p = 8) | Cạnh | Nút | Benign | PortScan | Heartbleed | Infiltration | DoS Hulk |
|---|---:|---:|---:|---:|---:|---:|---:|
| Paper Table II/VII | 33.228 | 40.744 | 5.000 | 6.451 | 1.468 | 1.764 | 5.000 |
| **`P_paper`** | **30.041** | **22.328** | **5.000** | **6.451** | 11 | 34 | **5.000** |

Hai lớp **không thể** tái lập từ artefact công khai: CSV chỉ có 11 dòng Heartbleed và 36 dòng Infiltration là luồng TCP, trong đó chỉ 11 và 34 dòng khớp được gói tin trong pcap (`scripts/check_paper_counts.py` báo `csv_pool_exhausted` thay vì tự sinh dữ liệu).

| Thiết lập | Luật | TPR @ FPR 6,56% (matched) | TPR @ FPR 1% | AUROC |
|---|---|---:|---:|---:|
| Paper Table VI | "majority" (thực tế là OR) | **99,04%** | — | — |
| `P_paper` | tie / strict / OR | **3,25%** | 1,39% | 0,478 |
| `P_paper` | INNE (detector tốt nhất) | 8,31% | 4,12% | 0,590 |
| `T` (cùng pipeline) | tie | 11,54% | 2,79% | 0,594 |

**Diễn giải:**
1. Khớp thành phần tập test **không** tạo ra con số 99%.
2. Zero-pad không phải nguồn "ăn may": các cạnh đủ 8 gói (DDoS, Hulk, GoldenEye; 17.018 cạnh) có AUROC 0,35 / 0,41 / 0,47 theo seed. Tức là các lớp tấn công chủ lực của bài báo lại chính là phần không tách được.
3. AUROC < 0,5 nghĩa là các luồng tấn công trông "bình thường" hơn benign. Giải thích khả dĩ: benign Friday của `P_paper` có nhiều luồng ngắn bị zero-pad, nên khác phân phối với train. Đây là điểm cần phân tích thêm (xem [`paper_parity.md`](paper_parity.md)).

### 4.4 Chuyển miền: CIC-IDS2018 và ACI-IoT-2023
Bài báo chỉ báo TPR trên tập test **toàn tấn công**. Nhóm đo lại có thêm benign để tính được FPR (cùng 25 byte, cùng 4 detector, p = 8):

| Bộ dữ liệu | Paper TPR | Nhóm TPR | Nhóm FPR | Nhóm AUROC |
|---|---:|---:|---:|---:|
| CIC-IDS2018 (1 ngày, Hulk) | 98,74% | 5,99% | 1,52% | 0,764 |
| ACI-IoT-2023 (khác ngày) | 98,21% | 1,69% | 1,11% | 0,536 |

### 4.5 Độ trễ thực tế ("real-time")
Đo bằng cách replay pcap Friday (`reports/latency.md`):
- Từ lúc luồng đóng đến lúc có cảnh báo: **122 ms/flow** (p50 48 ms), tương đương **15.272 µs/gói**.
- Chi phí lớn nhất là dựng **line graph** cho cửa sổ 120 s (72 ms) và chạy detector (36 ms).
- Thông lượng xử lý **8,2 flow/s**, trong khi lưu lượng đến là **12,1 flow/s**, nên **không theo kịp thời gian thực** trên 1 CPU.

Con số 1,28 µs/gói của bài báo chỉ đo phần chạy mô hình trên GPU, không tính trích đặc trưng và dựng đồ thị.

### 4.6 Tự đánh giá theo tiêu chí đặt ra từ đầu
Kế hoạch (`docs/GTAE-IDS_Research_docs.md` §0) đặt bốn tiêu chí thành công:

| Tiêu chí | Kết quả |
|---|---|
| Pipeline end-to-end, 1 lệnh train + 1 lệnh eval | **Đạt** |
| Có đường cong TPR/FPR theo p | **Đạt**, nhưng xu hướng "TPR tăng theo p" **không đạt** (§4.2) |
| Bảng "paper vs ours" có giải thích chênh lệch | **Đạt** (Chương 4.3, 5) |
| GTAE ≥ baseline không đồ thị B0 | **Không đạt**: AUROC B0 0,698 > M1 0,594 (Chương 6) |

---

## CHƯƠNG 5: ĐỐI CHIẾU BÀI BÁO VỚI MÃ NGUỒN CÔNG KHAI CỦA TÁC GIẢ

Nguồn: repo `jalalgh7/graph-representation-learning-for-NIDS` (mô hình, kết quả) và `jalalgh7/robust-and-real-time-NIDS` (trích xuất gói tin; `graph_generation/*.ipynb` của GTAE đọc trực tiếp file `.pkl` do repo này sinh ra). Chi tiết, kèm số cell và trích đoạn code: [`docs/REPRO_AUDIT.md`](../docs/REPRO_AUDIT.md) §5.

| # | Phát hiện | Mức độ kiểm chứng |
|---|---|---|
| F1 | Cột Ensemble của **Table VII trùng khớp từng chữ số** với output của `anomalies_ensemble = (votes >= 1)`, tức luật **OR** (cell 60 `GTAE_8pkt.ipynb`). Bài báo (tr. 4033) mô tả *majority voting* | Đã kiểm chứng |
| F2 | Table VI ghi FPR Ensemble **6,56%** (OCSVM 4,03%). CSV công khai của tác giả ghi FPR benign của Ensemble là **13,12%** (OCSVM 8,06%). Artefact công khai không tái tạo được điểm vận hành đã công bố | Đã kiểm chứng |
| F3 | Mỗi lớp tấn công được dựng thành **một đồ thị test riêng** (`create_graph_from_df` gọi cho từng lớp). Đồ thị chỉ có DoS (hub cực lớn) khác hẳn topo đồ thị benign, nên detector có thể dựa vào cấu trúc làm lối tắt | Đã định lượng: dựng lại đúng kiểu paper trên `P_paper` p8, TPR trên đồ thị chỉ-attack **không cao hơn** đồ thị trộn (PortScan 0,00% vs 6,32%; mọi lớp ≤0,98%) ⇒ topo không phải lối tắt mô hình nhóm khai thác được |
| F4 | Benign train và benign test cùng từ **Friday** (70/30). Bài báo **không** nêu ngày train; đây là điểm yếu phương pháp (không có dịch chuyển phân phối), không phải mâu thuẫn với nội dung bài báo | Đã kiểm chứng |
| F5 | Detector chạy trên **output của decoder** (`autoencoder(...)` trả về bản tái tạo 400 chiều), không phải embedding ở bottleneck như bài báo mô tả (§IV-C) | Đã kiểm chứng |
| F6 | Lớp `GraphAutoencoder` công bố không nối encoder vào decoder (`self.decoder(features)`), dùng `nn.GraphTransformerLayer` (không tồn tại trong PyTorch) và có `execution_count` lộn xộn. Kết luận: **notebook không phản ánh code đã sinh ra kết quả**. Nhóm **không** khẳng định mô hình thực tế là `Linear(400, 400)` | Đã kiểm chứng phần code |
| F7 | Trong repo trích xuất gói tin, gói nền trong cửa sổ tấn công không được gán nhãn (thiếu `else`). Cột nhãn được gán theo vị trí rồi `dropna()`, nên nhãn bị **trượt hàng** | Đã định lượng trên Thứ Ba: 269.201/851.306 gói bị bỏ qua, **13,9%** gói sai nhãn, precision nhãn tấn công **11,8%**, recall **14,8%**, **14,4%** flow bị ảnh hưởng |

**Kết luận:** F1 + F2 giải thích vì sao các con số công bố không tái tạo được từ artefact. F3 + F4 + F5 cho thấy thiết lập đánh giá của code dễ hơn nhiều so với tình huống triển khai thật. Phần còn lại của khoảng cách (Chương 4.3) cho thấy, ngay cả khi làm theo đúng thiết lập của bài báo, embedding GTAE vẫn không tách được benign khỏi tấn công.

---

## CHƯƠNG 6: SO SÁNH VỚI CÁC NGHIÊN CỨU LIÊN QUAN VÀ ĐÁNH GIÁ ƯU/NHƯỢC ĐIỂM

Chi tiết 12 bài liên quan: [`docs/GTAE-IDS_Research_docs.md`](../docs/GTAE-IDS_Research_docs.md) §3. Bảng số có ghi nguồn: [`related_work.md`](related_work.md).

### 6.1 Định vị GTAE-IDS giữa các hướng tiếp cận

| Bài | Đầu vào | Đồ thị | Học | Phát hiện sớm | Zero-day | Điểm khác chính so với GTAE |
|---|---|---|---|---|---|---|
| **GTAE-IDS [1]** | 25 byte header × p gói | Có (nút IP:port) | One-class AE + 4 detector | Có | Có | — |
| SPIN-IDS [2] | Header + payload, ảnh 2D | Không | Supervised CNN | Có (4–9 gói) | Không | Cùng tác giả; cần nhãn |
| PBCNN [4] | Byte thô của cả luồng | Không | Supervised CNN | Hạn chế | Không | Cần cả luồng |
| E-GraphSAGE [6] | NetFlow | Có | Supervised | Không | Không | Mean aggregation thay attention |
| Anomal-E [8] | NetFlow | Có (nút = IP) | Self-supervised DGI + detector | Không | Có | Cùng mô hình "GNN → detector cổ điển"; báo cả F1 |
| GraphIDS [10] | NetFlow | Có | GNN + Transformer MAE, end-to-end | Không | Có | Học biểu diễn và phát hiện trong một mục tiêu |
| Kitsune [11] | Thống kê theo gói | Không | Ensemble AE online | Có (theo gói) | Có | Streaming thật sự, chạy trên thiết bị nhẹ |

**Nhận xét:** GTAE là bài duy nhất trong nhóm kết hợp cả ba yếu tố (packet-level, đồ thị, không giám sát). Đây là điểm mới thật sự của bài báo. Đổi lại, nó không có baseline nào được đo trong cùng điều kiện: Table XI–XIII của bài báo so với các phương pháp supervised hoặc flow-based, trên tập chia cân bằng.

### 6.2 So sánh cùng protocol (nhóm tự cài đặt và đo)
Cùng dữ liệu (protocol `T`), cùng mã hoá 25 byte, cùng 4 detector, p = 8, mean ± std 3 seed ([`seed_stats.md`](seed_stats.md)):

| Phương pháp | Đại diện cho | TPR | FPR | AUROC | TPR@FPR=1%* |
|---|---|---:|---:|---:|---:|
| M1 GTAE (attention + LapPE) | [1] | 4,18 ± 4,30% | 2,79 ± 1,40% | 0,594 ± 0,106 | 3,65 ± 4,48% |
| **B2 E-GraphSAGE-AE** (mean aggregation, cùng độ sâu/độ rộng) | [6], encoder của [8] | **9,78 ± 9,76%** | 1,81 ± 1,72% | **0,689 ± 0,021** | **11,30 ± 10,52%** |
| **A2 GTAE bỏ LapPE** | ablation | 6,36 ± 3,72% | 1,23 ± 0,68% | **0,682 ± 0,003** | **12,46 ± 0,86%** |
| B1 MLP-AE (không đồ thị) | AE trong [11] | 6,29 ± 1,10% | 2,29 ± 0,17% | 0,595 ± 0,005 | 6,95 ± 1,70% |
| B0 vector thô (không học biểu diễn) | [4], [5] bản không giám sát | 0,50 ± 0,36% | 1,22 ± 0,05% | 0,698 ± 0,004 | 2,13 ± 0,25% |
| B0, chỉ HBOS | — | 0,00% | 1,66% | **0,810 ± 0,000** | 0,00% |
| A3 GTAE + reconstruction MSE | mục tiêu của [10] | 6,01 ± 9,69% | 2,07 ± 1,34% | 0,649 ± 0,012 | 6,01% |

\* Ngưỡng là quantile 99% của điểm trên `train2` (benign Monday). FPR thực trên benign test được ghi trong [`seed_stats.md`](seed_stats.md) và thường > 1% do dịch chuyển phân phối.

### 6.3 Các tuyên bố của bài báo, đối chiếu bằng số đo

| Tuyên bố của [1] | Số đo của nhóm | Kết luận |
|---|---|---|
| Graph transformer (attention giữa các cạnh) là thành phần cốt lõi | B2 mean aggregation có AUROC 0,689 ± 0,021, cao hơn và ổn định hơn M1 (0,594 ± 0,106) | **Không xác nhận.** Bài báo không có ablation này |
| Ngữ cảnh đồ thị giúp phát hiện (Table X: +4,4% TPR) | B0 không dùng đồ thị có AUROC 0,698 (HBOS 0,810) > M1 | **Không xác nhận** trong protocol `T` |
| Không phụ thuộc shortcut định danh (đã bỏ IP/port) | A5 xoá TTL + 2 checksum rồi train lại: AUROC 0,594 → 0,675 | **Xác nhận**: tín hiệu không đến từ các byte phụ thuộc địa chỉ |
| Real-time 1,28 µs/gói | 15.272 µs/gói end-to-end; 8,2 < 12,1 flow/s | **Không xác nhận** ở mức triển khai |
| Tổng quát hoá sang 2018/ACI (> 98%) | TPR 5,99% / 1,69% khi có benign trong test | **Không xác nhận**; bài báo không đo FPR trên 2018/ACI |

### 6.4 Về cách so sánh của bài báo
- Table XI so GTAE (không giám sát) với các GNN **có giám sát** dùng **flow hoàn chỉnh**, trên tập chia **cân bằng** benign/attack. Đây không phải cùng điều kiện.
- **Lưu ý khi đọc khoảng cách TPR:** với một ngưỡng cố định (lấy từ benign train2), TPR chỉ được tính trên mẫu tấn công nên **không phụ thuộc vào tỉ lệ benign/attack**; tỉ lệ này chỉ ảnh hưởng tới precision. Vì vậy khoảng cách 98,74% → 5,99% trên CIC-IDS2018 không thể giải thích bằng "mất cân bằng". Với mô hình đồ thị, nguyên nhân hợp lý hơn là **thành phần đồ thị**: đồ thị test chỉ có tấn công (như bài báo) có topo khác hẳn đồ thị trộn benign (như nhóm). Đây chính là phát hiện F3 ở Chương 5.

### 6.5 Tổng hợp ưu/nhược điểm của GTAE-IDS

**Ưu điểm (đã xác nhận được)**

| Ưu điểm | Bằng chứng |
|---|---|
| Kết hợp packet-level + đồ thị + không giám sát, chưa bài nào trong nhóm liên quan làm | §6.1 |
| Không cần nhãn tấn công để học biểu diễn | train chỉ dùng benign; zero-day về nguyên tắc |
| Đặc trưng 25 byte không chứa IP/port, không phụ thuộc TTL/checksum | test chống rò rỉ; A5 |
| Kiến trúc cài đặt được, kích thước nhỏ (p = 8: d = 64) | `src/model_gtae.py` |
| Cho phép quyết định theo p gói (khung cho phát hiện sớm) | P1 (Chương 7) |

**Nhược điểm (có số đo)**

| Nhược điểm | Bằng chứng |
|---|---|
| Embedding tách benign/attack kém khi có dịch chuyển phân phối theo thời gian (AUROC ~0,6) | §4.1 |
| Huấn luyện không ổn định theo seed (AUROC 0,495–0,705) | [`seed_stats.md`](seed_stats.md) |
| Attention và LapPE không mang lại lợi ích; còn làm kém và bất ổn hơn | B2, A2 (§6.2) |
| Đồ thị tĩnh theo cửa sổ: phải dựng lại line graph, nên không đạt thời gian thực | §4.5 |
| Ensemble 4 detector bằng phiếu cứng: không kiểm soát được FPR | §4.3; F1, F2 |
| Đánh giá trong bài báo: tập test toàn tấn công, đồ thị riêng từng lớp, benign cùng ngày | F3, F4; §4.4 |

---

## CHƯƠNG 7: ĐỀ XUẤT CẢI TIẾN

### 7.1 Chẩn đoán làm cơ sở cho đề xuất
Từ Chương 4–6, GTAE-IDS có hai điểm yếu nằm ở **hai tầng khác nhau**:
1. **Tầng biểu diễn:** embedding tách benign/attack kém và bất ổn theo seed. Attention và LapPE không giúp ích.
2. **Tầng quyết định:** phiếu cứng của 4 detector không cho phép chọn và **bảo đảm** FPR, và luôn phải chờ đủ p gói.

Đề xuất của nhóm giải quyết lần lượt từng tầng.

### 7.2 Đề xuất A (tầng biểu diễn): bộ mã hoá gọn hơn
**Nội dung:** thay attention giữa các cạnh bằng **mean aggregation** (E-GraphSAGE-AE, `src/model_egsage.py`, giữ nguyên độ sâu và độ rộng của `ARCH[p]`) và **bỏ LapPE**.

**Lý do:**
- Attention với softmax trên lân cận line graph có phương sai cao khi hub có bậc lớn (K_max = 32).
- LapPE có mơ hồ về dấu và phụ thuộc thành phần liên thông, nên thay đổi giữa đồ thị train và test.
- Mean aggregation và không dùng PE cho biểu diễn ổn định hơn với phân phối dịch chuyển.

**Kết quả đo (p = 8, protocol `T`, 3 seed):**

| | M1 (gốc) | A: bỏ LapPE | A: mean aggregation (B2) |
|---|---:|---:|---:|
| AUROC | 0,594 ± 0,106 | **0,682 ± 0,003** | **0,689 ± 0,021** |
| TPR @ ngưỡng FPR=1% | 3,65 ± 4,48% | **12,46 ± 0,86%** | **11,30 ± 10,52%** |
| TPR / FPR (tie) | 4,18% / 2,79% | 6,36% / 1,23% | 9,78% / 1,81% |
| Độ lệch chuẩn AUROC giữa seed | 0,106 | 0,003 (giảm ~35 lần) | 0,021 (giảm ~5 lần) |

**Đánh giá:**
- Cả hai biến thể đều cải thiện AUROC khoảng +0,09, giảm FPR, và tăng TPR tại FPR thấp gấp khoảng 3 lần.
- Mean aggregation còn **rẻ hơn**: không tính Q/K/V cho mỗi cặp cạnh, nên giảm phần `forward` vốn chiếm khoảng 11% độ trễ.
- **Giới hạn:** AUROC ~0,69 vẫn còn xa mức triển khai được. Đề xuất A cải thiện đáng kể so với GTAE nhưng không đóng được khoảng cách tới con số của bài báo.

### 7.3 Đề xuất B (tầng quyết định): P1, Calibrated Conformal Fusion & Sequential Early-Exit

**7.3.1 Conformal p-value và hợp nhất**
1. Chuyển điểm $s_m(x)$ của detector $m$ thành conformal p-value trên tập hiệu chuẩn benign $\mathcal{C}$:
   $$\pi_m(x) = \frac{1 + \sum_{c \in \mathcal{C}} \mathbb{I}(s_m(c) \ge s_m(x))}{1 + |\mathcal{C}|}$$
2. Hợp nhất M = 4 detector:
   - **Bonferroni:** $\pi_{\text{fused}} = \min(1, M \cdot \min_m \pi_m)$. FPR ≤ α khi calibration và benign test exchangeable, **không** cần giả định các detector độc lập.
   - **Fisher:** $T = -2\sum_m \ln \pi_m \sim \chi^2(2M)$. Chỉ đúng khi các p-value độc lập, nên chỉ dùng để thăm dò (exploratory).

**7.3.2 Early-exit tuần tự**
- Tại mỗi p = 2, 3, …, 8 dùng ngân sách $\alpha_p = \alpha / 7$ (Bonferroni qua 7 bước, nên tổng FPR ≤ α).
- Nếu $\pi_{\text{fused},p}(x) \le \alpha_p$: báo động ngay, dừng thu thập gói, ghi `p_decision = p`.
- Đến p = 8 mà chưa báo động thì kết luận benign.
- Dùng 800 flow calibration (40% `train2`). Với 400 flow, p-value nhỏ nhất là $4/401 > 0{,}05/7$, nên Bonferroni ở α = 0,05 **không bao giờ** báo động được.

**7.3.3 Kết quả (T_fixed, mean ± std 3 seed; [`P1.md`](P1.md))**

| α | Fusion | TPR | FPR thực đo | Số gói TB đến quyết định (attack) | Tỉ lệ dừng sớm (attack) | AUROC |
|---|---|---:|---:|---:|---:|---:|
| 0,05 | **Bonferroni** | **8,95 ± 3,72%** | **3,64 ± 1,00%** (≤ 5%) | 7,75 | 7,70% | 0,662 ± 0,021 |
| 0,10 | **Bonferroni** | **14,11 ± 2,11%** | **5,78 ± 1,35%** (≤ 10%) | 7,56 | 13,22% | 0,662 ± 0,021 |
| 0,01 | Bonferroni | 0% | 0% | 8,00 | 0% | 0,662 |
| 0,05 | Fisher (exploratory) | 47,53 ± 4,23% | 18,86 ± 4,81% (> α) | 6,24 | 46,98% | 0,639 |

**Đánh giá trung thực:**
1. **Đạt:** Bonferroni giữ FPR thực đo ≤ α ở cả α = 0,05 và α = 0,10, trên benign của **ngày khác** với calibration. Đây là thứ phiếu cứng của bài báo không làm được: người vận hành chọn trước mức báo động giả chấp nhận được.
2. **Hạn chế về lý thuyết:** calibration (Monday) và benign test (Tue–Fri) không exchangeable, nên "FPR ≤ α" ở đây là **quan sát thực nghiệm**, không còn là bảo đảm lý thuyết.
3. **Hạn chế về hiệu quả:** AUROC chỉ tăng từ 0,594 lên 0,662; TPR@FPR=1% của Bonferroni là 0%, thấp hơn M1 (3,65%). Phát hiện sớm có tác dụng nhỏ (số gói trung bình 7,56–7,75 so với 8).
4. **Fisher** cho TPR cao nhưng FPR vượt α do 4 detector tương quan. Không dùng để khẳng định kiểm soát FPR.
5. **Chi phí:** cần chạy 7 mô hình (mỗi p một mô hình); early-exit không giảm chi phí dựng đồ thị (§4.5).

### 7.4 Kết hợp A + B và các bước tiếp theo
Đề xuất B chỉ thay tầng quyết định nên bị giới hạn bởi chất lượng embedding (AUROC ~0,6). Kết hợp với Đề xuất A là bước hợp lý tiếp theo. Script đã hỗ trợ sẵn checkpoint E-GraphSAGE (`src/embed.load_model` đọc `arch_name`). P1 cũng đã ghi thêm TPR tại FPR 3% và 5% để so với M1 **ở cùng FPR** (kết quả trong `results/P1_summary.csv`: Bonferroni 1,82% @ 3% và 10,17% @ 5%; M1 đạt 4,18% ở FPR riêng 2,79% và 3,65% ở FPR=1% — nên ngay cả khi nới FPR lên 3–5%, P1 vẫn chưa vượt M1 ở vùng FPR thấp):

```bash
# P1 trên encoder B2 (đã có checkpoint p = 2, 4, 8)
PYTHONPATH=. python scripts/eval_baselines_p1.py --p1-only \
  --models experiments/T_egsage --p1-ps 2 4 8 --results results/P1_egsage
# Đối chứng: P1 trên GTAE với cùng p = 2, 4, 8
PYTHONPATH=. python scripts/eval_baselines_p1.py --p1-only \
  --models experiments/T --p1-ps 2 4 8 --results results/P1_p248
```

Các hướng khác đã cân nhắc (`docs/GTAE-IDS_Research_docs.md` §6), xếp theo mức độ nhắm vào điểm nghẽn biểu diễn:
- **P4 – nút = IP và đặc trưng nút nhẹ** (theo Anomal-E [8], Kitsune [11]): giảm phân mảnh đồ thị do port tạm thời.
- **P5 – mục tiêu masked reconstruction** (GraphMAE [14]): buộc mô hình dùng ngữ cảnh thay vì sao chép đặc trưng cạnh.
- **Online conformal / calibration theo cửa sổ trượt:** khôi phục giả định exchangeable khi phân phối trôi theo thời gian.

---

## CHƯƠNG 8: KẾT LUẬN

1. **Tìm hiểu bài báo:** nhóm phân tích đầy đủ phương pháp, cài đặt đúng Table III/V và Fig. 3/4, và liệt kê những điểm bài báo không mô tả nhưng ảnh hưởng tới khả năng tái lập (§2.5).
2. **Tái hiện:** pipeline hoàn chỉnh từ pcap, 132 test, 428 kiểm tra artefact, 4 protocol. Con số 99,04% @ 6,56% **không tái lập được**, kể cả trong thiết lập giống bài báo nhất (`P_paper`: 3,25%). Nhóm báo cáo phương sai giữa các seed và các tiêu chí không đạt.
3. **Đối chiếu và so sánh:**
   - Nhóm kiểm chứng được các mâu thuẫn giữa bài báo, code và CSV của tác giả (luật OR, FPR không khớp, test theo từng lớp, notebook không chạy được).
   - Baseline cùng protocol cho thấy attention, LapPE và ngữ cảnh đồ thị đều không phải nguồn tín hiệu.
   - Claim "real-time" không đúng ở mức triển khai.
4. **Đề xuất:**
   - (A) Mean aggregation / bỏ LapPE: AUROC +0,09, ổn định hơn 5–38 lần, TPR@FPR=1% gấp khoảng 3 lần.
   - (B) Conformal early-exit: FPR thực đo ≤ α nhưng TPR tăng ít.
   - Kết hợp A + B là hướng tiếp theo, đã có sẵn lệnh chạy.

**Hạn chế của đồ án:**
- **Seed:** 7 seed cho M1 ở mọi p (đường cong §4.2) nhưng 3 seed cho baseline/P1; và 7 seed vẫn chưa đủ để kết luận chênh lệch <1 sd — ví dụ B2−M1 = 0,096 với sd của chênh lệch ghép cặp là 0,093.
- Đã tải và đối chiếu **3 PDF gốc** (E-GraphSAGE, Anomal-E, Pujol-Perich, trong `docs/related/`): Anomal-E khớp chính xác (86,28→94,51 macro-F1); dòng E-GraphSAGE của Table XI **không có trong bài gốc** (bài gốc dùng NF-UNSW-NB15/NF-ToN-IoT/NF-BoT-IoT, metric F1/FAR); Pujol khớp một phần (accuracy từng lớp, thiếu Heartbleed/Infiltration). PBCNN, SPIN-IDS, GraphDDoS, GraphIDS vẫn là nguồn thứ cấp (paywall/không tìm thấy PDF) — chi tiết `reports/related_work_verification.md`.
- F3 và F7 **đã định lượng** (Chương 5; `results/per_class_graphs.csv`, `results/label_shift_f7.csv`), nên không còn là hạn chế mở; phần chưa làm là các biến thể robustness/online khác trong `docs/GTAE-IDS_Research_docs.md` §6.

---

## PHỤ LỤC A — TÁI LẬP KẾT QUẢ

Mọi số trong báo cáo sinh từ `results/*.csv`; các lệnh dưới chạy từ gốc repo với `.venv/bin/python`.

```bash
# 1. Dữ liệu → đồ thị (CIC-IDS2017, protocol T/R/T_fixed)
python -m src.parse_pcap --pcap data/raw/Wednesday-workingHours.pcap --out data/processed --day wednesday
python -m src.label --flows data/processed/flows_wednesday.parquet --offset-minutes -180 \
  --out data/processed/flows_wednesday_labeled.parquet
python -m src.build_dataset --p 2 3 4 5 6 7 8 --out data/graphs

# 2. Huấn luyện + đánh giá (21 model = 7 p × 3 seed; + 28 model seed 3..6 để đo bất định)
python scripts/train_all.py --graphs data/graphs/T --out experiments/T --ps 2 3 4 5 6 7 8 --device cpu
python -m src.eval --models experiments/T --graphs data/graphs/T --out results \
  --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --device cpu
python scripts/train_all.py --graphs data/graphs/T --out experiments/T_probe \
  --ps 2 3 4 5 6 7 8 --seeds 3 4 5 6 --patience 100 --device cpu
python -m src.eval --models experiments/T_probe --graphs data/graphs/T \
  --out results/probe_extra_seeds --ps 2 3 4 5 6 7 8 --seeds 3 4 5 6 --device cpu

# 3. Baseline + P1 + ablation
PYTHONPATH=. python scripts/eval_baselines_p1.py --calibration-fraction 0.4
python scripts/eval_recon_ablation.py --graphs data/graphs/T --models experiments/T \
  --ps 2 4 8 --seeds 0 1 2 --out results --device cpu
python scripts/eval_hygiene.py --ps 8 --seeds 0 1 2 --device cpu
python scripts/make_ablation_report.py && python scripts/make_p1_report.py

# 4. Paper-parity (Table II/V/VI/VII) + p-curve
python scripts/build_paper_graphs.py --out data/graphs/P_paper --ps 2 3 4 5 6 7 8 --seed 0
python scripts/train_all.py --graphs data/graphs/P_paper --out experiments/P_paper --ps 8 --device cpu
python scripts/eval_paper_parity.py --protocols P_paper T --ps 8 --seeds 0 1 2 \
  --out results/paper_parity --device cpu --write-report --diagnostics
python scripts/check_paper_counts.py --all-p

# 5. Chuyển miền 2018 + ACI, độ trễ, seed variance, F3, F7
python scripts/build_cross_dataset_graphs.py --processed data/processed/2018 --out data/graphs/2018
python scripts/build_cross_dataset_graphs.py --processed data/processed/aci --out data/graphs/aci \
  --train-tags aci_benign1 --test-benign-tags aci_benign2
python scripts/eval_latency.py --mode stream --pcap data/raw/Friday-WorkingHours.pcap \
  --day friday --graphs data/graphs/T --models experiments/T_noPE --p 8 --out results
python scripts/make_seed_stats.py
python scripts/eval_per_class_graphs.py --p 8 --seeds 0 1 2
python scripts/eval_label_shift.py --day tuesday --offset-minutes -180
python scripts/eval_wait_p.py --out results/wait_p.csv

# 6. Kiểm chứng
pytest -q                     # 126+ test
python scripts/audit_artifacts.py   # 428/428
```

## PHỤ LỤC B — BẢNG SỐ LIỆU ↔ TỆP KẾT QUẢ

| Bảng trong báo cáo | Tệp nguồn |
|---|---|
| §4.1 kết quả chính p=8 | `results/M1_summary.csv`, `results/noPE/`, `results/B0_summary.csv`, `results/B1_summary.csv`, `results/B2/M1_summary.csv`, `results/A3_recon.csv`, `results/A5_hygiene.csv` |
| §4.2 đường cong p | `results/M1_summary.csv`; độ bất định seed: `results/seed_stats.csv` |
| §4.3 P_paper (Table II/VI/VII) | `results/paper_parity/p*_selected.csv`, `p8_per_class.csv`, `p8_padding_diag.csv`, `results/P_paper_table2.csv` |
| §4.4 chuyển miền | `results/2018/M1_summary.csv`, `results/aci/M1_summary.csv` |
| §4.5 độ trễ | `results/latency.csv`, `results/latency_summary.json`, `results/early_exit_timing.csv` |
| §5 F1–F7 | `docs/REPRO_AUDIT.md`; F3: `results/per_class_graphs.csv`; F7: `results/label_shift_f7.csv` |
| Chương 6 related work | `reports/related_work.md`, `reports/related_work_verification.md` |
| Chương 7 P1 | `results/P1_summary.csv`, `results/P1_meta.json`, `reports/P1.md` |
| Chương 8 hạn chế | `results/seed_stats.csv`, `docs/DECISIONS.md` |
