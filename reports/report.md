# BÁO CÁO NGHIÊN CỨU ĐỒ ÁN MÔN HỌC
## HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG THỜI GIAN THỰC DỰA TRÊN ĐỒ THỊ BIẾN ĐỔI TỰ MÃ HÓA (GTAE-IDS)
### TÁI HIỆN ĐỘC LẬP, ĐỐI CHIẾU MÃ NGUỒN GỐC, SO SÁNH VỚI CÁC NGHIÊN CỨU LIÊN QUAN VÀ ĐỀ XUẤT CẢI TIẾN

---

**Môn học:** Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập (NT204.R11.ANTN)

**Nhóm:** 8

| MSSV | Họ và tên |
|---|---|
| 24521675 | Đinh Quốc Thịnh |
| 24520021 | Lê Xuân Nguyên |
| 24521208 | Trần Đình Nguyên |

**Bài báo nghiên cứu cơ sở (paper neo):**

> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026-4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

**Mã nguồn:** [github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS)

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

**Kết quả tái hiện:** con số công bố **TPR 99,04% @ FPR 6,56%** không tái lập được bằng một cài đặt đúng. Nó chỉ xuất hiện khi tái tạo **artifact mã hoá hướng** trong pipeline của tác giả: trên `T`, bỏ phiếu >=3/4 cho **99,22% @ 6,66% FPR** (seed 0; 99,22-99,99% @ 6,52-6,66% qua 3 seed) - trùng Table VI trong 0,2 pp TPR và 0,1 pp FPR.
- Protocol `T` (train benign Monday, test Tue-Fri) đạt TPR **4,18 ± 4,30%** @ FPR **2,79 ± 1,40%**, AUROC **0,594 ± 0,106** (3 seed).
- Protocol `P_paper` dựng lại đúng thành phần test của Table II/VII và đúng luật OR trong code tác giả, nhưng vẫn chỉ đạt **3,25%** TPR tại cùng FPR 6,56%.

**Đối chiếu bài báo với mã nguồn công khai** (Chương 5). Nhóm kiểm chứng được:
- Table VII trùng khớp từng số với luật **OR** (`votes >= 1`), trong khi bài báo mô tả *majority voting*.
- FPR Ensemble công bố (6,56%) không khớp CSV công khai của tác giả (13,12%).
- Mỗi lớp tấn công được test trên **một đồ thị riêng**, benign train/test cùng **một ngày**.
- Detector chạy trên **output của decoder**, và notebook công bố **không chạy được** như hiện có.
- **Truy vết được nguồn gốc của 99%**: pipeline trích xuất của tác giả gán `Direction='unknown'` cho benign và dồn các gói này vào nửa sau của vector, trong khi attack giữ fwd/bwd. Một luật một bit đạt **TPR 100% / FPR 0%**; khi mã hoá hướng nhất quán, cả classifier giám sát cross-day cũng chỉ đạt 3,5-23% TPR.

**So sánh với nghiên cứu liên quan** (Chương 6). Các baseline cùng protocol cho thấy:
- **Attention không phải nguồn tín hiệu**: E-GraphSAGE-AE (mean aggregation) đạt AUROC **0,689 ± 0,021**, cao hơn GTAE.
- **Ngữ cảnh đồ thị chưa giúp ích**: vector header thô (B0) đạt AUROC **0,698**.
- **"Real-time" không đạt ở mức triển khai**: 8,2 flow/s, trong khi lưu lượng đến là 12,1 flow/s.

**Đề xuất cải tiến** (Chương 7) gồm hai tầng:
- **(A) Tầng biểu diễn:** thay attention bằng mean aggregation và bỏ LapPE. Đã đo: AUROC tăng từ 0,594 lên 0,68-0,69, độ lệch chuẩn giữa các seed giảm 5-38 lần, TPR@FPR=1% tăng từ 3,65% lên 11-12%.
- **(B) Tầng quyết định (P1):** conformal p-value kết hợp early-exit tuần tự theo p. Bonferroni giữ được FPR thực đo ≤ α (3,64% @ α=0,05; 5,78% @ α=0,10), nhưng TPR tăng ít và tại FPR=1% không vượt M1.

Nhóm trình bày cả những tiêu chí **không đạt**: đường cong TPR theo p không đơn điệu, GTAE không vượt baseline không dùng đồ thị.

---

## CHƯƠNG 1: GIỚI THIỆU VÀ ĐỘNG CƠ NGHIÊN CỨU

### 1.1 Bài toán phát hiện xâm nhập mạng (NIDS)
- **NIDS dựa trên luật (signature-based)** như Snort/Suricata: chính xác với tấn công đã biết nhưng bất lực trước tấn công zero-day.
- **NIDS dựa trên thống kê luồng (flow-based)**: dùng CICFlowMeter trích 80+ đặc trưng thống kê. Điểm yếu là **độ trễ**: phải chờ luồng kết thúc hoặc hết timeout (120 s) mới có đặc trưng, nên không thể chặn tấn công ngay trên đường truyền (in-line).
- **NIDS học có giám sát (supervised)**: cần nhãn tấn công, và chủ yếu nhận ra các tấn công giống với dữ liệu huấn luyện.

### 1.2 Động cơ của GTAE-IDS
Bài báo đặt ra ba mục tiêu (§I, tr. 4026-4027):
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
- Attention tính giữa các cạnh **chung đầu mút**, tức là trên **line graph** L(G), theo eq. (4)-(8):
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
- Table VI, p = 8: Ensemble **TPR 99,04% / FPR 6,56%**; các detector đơn có FPR 4,03-4,99%.
- Table VII: TPR theo từng lớp tấn công đều > 98,5%.
- Table VIII: TPR > 98% trên CIC-IDS2018 và ACI-IoT-2023. Lưu ý: các tập test này **chỉ có lưu lượng tấn công**, nên không đo được FPR.
- Table XII: thời gian suy luận **1,28 µs/gói**.

### 2.5 Những điểm bài báo không mô tả rõ
Đây là các điểm ảnh hưởng trực tiếp tới khả năng tái lập. Nhóm phải tự giả định (chi tiết ở Phụ lục F):

| Điểm chưa rõ | Hệ quả | Lựa chọn của nhóm |
|---|---|---|
| Benign train/test lấy từ ngày nào | Không biết có dịch chuyển phân phối giữa train và test không | Protocol `T` (Monday → Tue-Fri) làm chính; `P_paper` (Friday) để đối chứng |
| Đồ thị test trộn benign + attack hay tách riêng từng lớp | Topo của đồ thị chỉ có attack có thể tự "lộ" nhãn | Trộn chung (đúng tình huống triển khai) |
| Chiều LapPE, kích thước subgraph khi train, K_max | Ảnh hưởng tới huấn luyện | k = 8, ≤ 200 cạnh, K_max = 32 |
| Luật hoà phiếu 2-2 | Định nghĩa "majority" với 4 detector | Báo cả `strict` (≥ 3/4) và `tie` (≥ 2/4) |
| "1,28 µs/gói" đo những công đoạn nào | Không biết claim "real-time" bao gồm những gì | Đo end-to-end trên replay pcap (Chương 4.5) |

---

## CHƯƠNG 3: TÁI HIỆN PHƯƠNG PHÁP

### 3.1 Pipeline
Toàn bộ pipeline viết bằng Python/PyTorch thuần (không dùng PyG):

| Bước | Module | Ghi chú |
|---|---|---|
| Đọc pcap, tách luồng | [src/parse_pcap.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/parse_pcap.py) | Streaming; 5-tuple; kết thúc luồng khi idle > 120 s hoặc gặp SYN mới sau FIN/RST |
| Gán nhãn | [src/label.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/label.py) | Lịch tấn công CIC + đối chiếu với CSV CICFlowMeter; gắn nhãn `UNCERTAIN` khi không chắc |
| Mã hoá 25 byte | [src/packet_encoder.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/packet_encoder.py) | Kiểm chứng bằng test vector theo Fig. 3 |
| Dựng đồ thị, line graph, LapPE | [src/graph_builder.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/graph_builder.py), [src/line_graph.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/line_graph.py), [src/pe.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/pe.py) | LapPE dùng vector khởi tạo ARPACK có seed |
| Mô hình | [src/model_gtae.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/model_gtae.py) | `ARCH` khớp Table III cho p = 2..8 |
| Huấn luyện | [src/train_gtae.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/train_gtae.py) | Adam, lr 1e-3, 100 epoch, 50 subgraph/batch |
| Detector, đánh giá | [src/detectors.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/detectors.py), [src/eval.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/eval.py) | Đúng siêu tham số Table V |

Các protocol đánh giá:
- **`T` (chính):** train1/train2 lấy benign Monday; test lấy Tue-Fri (5.000 benign + tối đa 5.000 flow mỗi lớp tấn công).
- **`T_fixed`:** cùng một quần thể 30.907 flow có ≥ 8 gói cho mọi p, để so sánh công bằng giữa các p.
- **`R`:** chia ngẫu nhiên theo flow, gần với cách hiểu "snapshot" của bài báo.
- **`P_paper`:** dựng theo dòng CSV CICFlowMeter, đúng số lượng từng lớp như Table VII, đúng grid contamination, đúng luật OR của code (Chương 4.3).

**Quy trình huấn luyện:** 21 mô hình canonical (7 giá trị p × 3 seed) + 28 mô hình bổ sung (4 seed × 7 p, `experiments/T_probe`) để đo độ bất định; lần đầu chạy trên Kaggle T4, bản cuối được huấn luyện lại từ đầu trên CPU ngày 2026-11-16.

### 3.2 Kiểm thử và chống rò rỉ dữ liệu
- **132 test `pytest` pass**: không có IP/port trong đặc trưng, các split rời nhau, train chỉ có benign, test cho conformal/early-exit, test cho script thống kê seed.
- Kiểm tra tự động trên artefact: **428/428** phép kiểm tra chéo trên artefact thật (khoá ngoại packet ↔ flow, mã hoá lại, nhãn, split, dựng lại đồ thị tất định).

---

## CHƯƠNG 4: KẾT QUẢ TÁI HIỆN VÀ ĐÁNH GIÁ

### 4.1 Kết quả chính (p = 8, protocol `T`, mean ± std 3 seed)

| Phương pháp | TPR | FPR | AUROC [min-max] |
|---|---:|---:|---:|
| **Paper Table VI** (Ensemble) | 99,04% | 6,56% | - |
| **M1: GTAE tái hiện** (ensemble tie) | **4,18 ± 4,30%** | **2,79 ± 1,40%** | **0,594 ± 0,106** [0,495-0,705] |
| M1, chỉ INNE | 8,69 ± 12,30% | 1,84 ± 1,37% | 0,578 ± 0,116 |

**Phương sai giữa các seed rất lớn:** AUROC của 3 seed là 0,705 / 0,581 / 0,495; seed kém nhất gần như đoán ngẫu nhiên. Vì vậy với 3 seed, mọi chênh lệch nhỏ hơn khoảng 1 std **không** đủ để kết luận. Tuy nhiên, khoảng cách tới con số 99% của bài báo lớn hơn hàng chục lần độ lệch chuẩn, nên kết luận "không tái lập được" vẫn đứng vững.

### 4.2 Đường cong theo p (ensemble tie; 7 seed mỗi p)

| p | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|
| TPR (%) | 2,99 ± 1,66 | 7,31 ± 4,35 | 9,29 ± 5,83 | 8,82 ± 8,74 | 9,21 ± 8,93 | 4,43 ± 7,46 | 7,63 ± 6,56 |
| AUROC | 0,499 ± 0,022 | 0,494 ± 0,024 | 0,597 ± 0,044 | 0,680 ± 0,020 | **0,774 ± 0,068** | 0,709 ± 0,157 | 0,663 ± 0,092 |
| AUROC min-max | 0,470-0,529 | 0,468-0,525 | 0,542-0,681 | 0,650-0,715 | 0,698-0,886 | 0,460-0,843 | 0,495-0,750 |

Bảy seed mỗi p (3 canonical + 4 bổ sung). So với 3 seed, p=8 tăng từ 0,594 lên **0,663 ± 0,092** - cú rơi ở p=8 một phần là nhiễu seed. Nhưng đường cong vẫn **không đơn điệu**: AUROC đỉnh ở p=6 rồi giảm ở p=7-8, TPR cũng vậy. Tiêu chí "TPR tăng theo p" vì thế **không đạt ngay cả với 7 seed** - đây là kết quả đo, không phải thiếu mẫu. Khoảng cách tới 99,04% của bài báo vẫn lớn hơn nhiều lần độ lệch chuẩn.

So trực tiếp với Table VI ở **cùng FPR 6,56%** (thay vì ngưỡng riêng của từng bên):

| p | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Paper TPR (%) | 84,47 | 91,02 | 94,72 | 97,16 | 98,44 | 98,72 | **99,04** |
| `T` TPR @6,56 (%) | 10,22 | 8,37 | 19,67 | 11,48 | **33,77** | 19,99 | 11,54 |
| `P_paper` TPR @6,56 (%) | 3,79 | 12,47 | 5,36 | 1,10 | 5,40 | 26,77 | 3,25 |

Paper tăng đơn điệu; nhóm không đơn điệu và thấp hơn 3-30 lần. Paper FPR dao động 5,91-8,94%
giữa các p, nên cột so sánh chỉ gần đúng về điểm vận hành.

### 4.3 Dựng lại đúng thiết lập của bài báo (`P_paper`)
Để loại trừ khả năng "kết quả âm chỉ là do cách dựng tập test của nhóm", nhóm dựng protocol `P_paper`:
- lấy **dòng CSV CICFlowMeter làm định nghĩa luồng** (đúng cách bài báo đếm cạnh);
- chọn đúng số lượng từng lớp theo Table VII; **zero-pad** các luồng ngắn thay vì loại bỏ;
- benign lấy từ Friday, như code của tác giả.

| Tập test (p = 8) | Cạnh | Nút | Benign | PortScan | Heartbleed | Infiltration | DoS Hulk |
|---|---:|---:|---:|---:|---:|---:|---:|
| Paper Table II/VII | 33.228 | 40.744 | 5.000 | 6.451 | 1.468 | 1.764 | 5.000 |
| **`P_paper`** | **30.041** | **22.328** | **5.000** | **6.451** | 11 | 34 | **5.000** |

Hai lớp **không thể** tái lập từ artefact công khai: CSV chỉ có 11 dòng Heartbleed và 36 dòng Infiltration là luồng TCP, trong đó chỉ 11 và 34 dòng khớp được gói tin trong pcap (kiểm tra số lượng tự động ghi nhận `csv_pool_exhausted` thay vì tự sinh dữ liệu).

| Thiết lập | Luật | TPR @ FPR 6,56% (matched) | TPR @ FPR 1% | AUROC |
|---|---|---:|---:|---:|
| Paper Table VI | majority (>=3/4) | **99,04%** | - | - |
| Paper Table VII / CSV | OR (>=1/4) | 98,50-99,83% (per-class) | - | - |
| `P_paper` | tie / strict / OR | **3,25%** | 1,39% | 0,478 |
| `P_paper` | INNE (detector tốt nhất) | 8,31% | 4,12% | 0,590 |
| `T` (cùng pipeline) | tie | 11,54% | 2,79% | 0,594 |

**Diễn giải:**
1. Khớp thành phần tập test **không** tạo ra con số 99%.
2. Zero-pad không phải nguồn "ăn may": các cạnh đủ 8 gói (DDoS, Hulk, GoldenEye; 17.018 cạnh) có AUROC 0,35 / 0,41 / 0,47 theo seed. Tức là các lớp tấn công chủ lực của bài báo lại chính là phần không tách được.
3. AUROC < 0,5 nghĩa là các luồng tấn công trông "bình thường" hơn benign. Giải thích khả dĩ: benign Friday của `P_paper` có nhiều luồng ngắn bị zero-pad, nên khác phân phối với train. Đây là điểm cần phân tích thêm (xem `paper_parity.md`).

### 4.4 Chuyển miền: CIC-IDS2018 và ACI-IoT-2023
Bài báo chỉ báo TPR trên tập test **toàn tấn công**. Nhóm đo lại có thêm benign để tính được FPR (cùng 25 byte, cùng 4 detector, p = 8):

| Bộ dữ liệu | Paper TPR | Nhóm TPR | Nhóm FPR | Nhóm AUROC |
|---|---:|---:|---:|---:|
| CIC-IDS2018 (1 ngày, Hulk) | 98,74% | 5,99% | 1,52% | 0,764 |
| ACI-IoT-2023 (khác ngày) | 98,21% | 1,69% | 1,11% | 0,536 |

### 4.5 Độ trễ thực tế ("real-time")
Đo bằng cách replay pcap Friday (chi tiết ở Phụ lục E.5):
- Từ lúc luồng đóng đến lúc có cảnh báo: **122 ms/flow** (p50 48 ms), tương đương **15.272 µs/gói**.
- Chi phí lớn nhất là dựng **line graph** cho cửa sổ 120 s (72 ms) và chạy detector (36 ms).
- Thông lượng xử lý **8,2 flow/s**, trong khi lưu lượng đến là **12,1 flow/s**, nên **không theo kịp thời gian thực** trên 1 CPU.

Con số 1,28 µs/gói của bài báo chỉ đo phần chạy mô hình trên GPU, không tính trích đặc trưng và dựng đồ thị.


---

## CHƯƠNG 5: ĐỐI CHIẾU BÀI BÁO VỚI MÃ NGUỒN CÔNG KHAI CỦA TÁC GIẢ

Nguồn: repo `jalalgh7/graph-representation-learning-for-NIDS` (mô hình, kết quả) và `jalalgh7/robust-and-real-time-NIDS` (trích xuất gói tin; `graph_generation/*.ipynb` của GTAE đọc trực tiếp file `.pkl` do repo này sinh ra). Chi tiết kỹ thuật, kèm trích đoạn code: Phụ lục F.

| # | Phát hiện | Mức độ kiểm chứng |
|---|---|---|
| F1 | Cột Ensemble của **Table VII trùng khớp từng chữ số** với output của `anomalies_ensemble = (votes >= 1)`, tức luật **OR** (cell 60 `GTAE_8pkt.ipynb`). Bài báo (tr. 4033) mô tả *majority voting* | Đã kiểm chứng |
| F2 | Table VI ghi FPR Ensemble **6,56%** (OCSVM 4,03%). CSV công khai của tác giả ghi FPR benign của Ensemble là **13,12%** (OCSVM 8,06%). Artefact công khai không tái tạo được điểm vận hành đã công bố | Đã kiểm chứng |
| F3 | Mỗi lớp tấn công được dựng thành **một đồ thị test riêng** (`create_graph_from_df` gọi cho từng lớp). Đồ thị chỉ có DoS (hub cực lớn) khác hẳn topo đồ thị benign, nên detector có thể dựa vào cấu trúc làm lối tắt | Đã định lượng: dựng lại đúng kiểu paper trên `P_paper` p8, TPR trên đồ thị chỉ-attack **không cao hơn** đồ thị trộn (PortScan 0,00% vs 6,32%; mọi lớp ≤0,98%) ⇒ topo không phải lối tắt mô hình nhóm khai thác được |
| F4 | Benign train và benign test cùng từ **Friday** (70/30). Bài báo **không** nêu ngày train; đây là điểm yếu phương pháp (không có dịch chuyển phân phối), không phải mâu thuẫn với nội dung bài báo | Đã kiểm chứng |
| F5 | Detector chạy trên **output của decoder** (`autoencoder(...)` trả về bản tái tạo 400 chiều), không phải embedding ở bottleneck như bài báo mô tả (§IV-C) | Đã kiểm chứng |
| F6 | Lớp `GraphAutoencoder` công bố không nối encoder vào decoder (`self.decoder(features)`), dùng `nn.GraphTransformerLayer` (không tồn tại trong PyTorch) và có `execution_count` lộn xộn. Kết luận: **notebook không phản ánh code đã sinh ra kết quả**. Nhóm **không** khẳng định mô hình thực tế là `Linear(400, 400)` | Đã kiểm chứng phần code |
| F7 | Trong repo trích xuất gói tin, gói nền trong cửa sổ tấn công không được gán nhãn (thiếu `else`). Cột nhãn được gán theo vị trí rồi `dropna()`, nên nhãn bị **trượt hàng** | Đã định lượng trên Thứ Ba: 269.201/851.306 gói bị bỏ qua, **13,9%** gói sai nhãn, precision nhãn tấn công **11,8%**, recall **14,8%**, **14,4%** flow bị ảnh hưởng |
| F8 | Detector trong code dùng **contamination 0,06/0,09**, không phải 0,01 như Table V | Đã kiểm chứng; giải thích FPR 9-13% của CSV |
| F9 | **Hướng gói tin mã hoá nhãn:** benign nhận `Direction='unknown'` và bị dồn vào nửa sau của vector 50 chiều; attack giữ fwd/bwd | Đã kiểm chứng ở code + tái tạo số: luật 1 bit **TPR 100% / FPR 0%**; detector của tác giả 100% TPR @ 17,7% FPR, khớp CSV (13,12%) |
| F10 | Checkpoint công bố (8 lớp, d_model 400, decoder 400×400) không khớp Table III (6 lớp, d=64) và không tái tạo CSV trên dữ liệu nhóm | Đã kiểm chứng: FPR ensemble 19,5%, TPR theo lớp 2,9-81,8% |

**Kết luận:** F1 + F2 + F8 cho thấy con số công bố không tái tạo được từ artefact, và bản thân các artefact mâu thuẫn nhau. F3 + F4 + F5 cho thấy thiết lập đánh giá của code dễ hơn nhiều so với triển khai thật. **F9 là mắt xích còn thiếu: nó biến 99% thành một artifact mã hoá, không phải năng lực của mô hình** (mục 5.1). Phần còn lại của khoảng cách (Chương 4.3) cho thấy, ngay cả khi làm theo đúng thiết lập của bài báo, embedding GTAE vẫn không tách được benign khỏi tấn công.

### 5.1 Vì sao không thể khớp 99%: phân rã khoảng cách

**Bốn phiên bản của "con số mục tiêu".** Không có một mục tiêu duy nhất để so:

| Nguồn | TPR | FPR | Ghi chú |
|---|---:|---:|---|
| Paper, Table VI (p=8) | 99,04% | 6,56% | Ensemble; OCSVM 98,46/4,03; IF 96,66/4,93; HBOS 97,73/4,96; INNE 96,47/4,99 |
| CSV công khai của tác giả | 98,50-99,83% theo lớp | **13,12%** | Cùng file sinh Table VII (F1) |
| Code công bố (cell 55-59) | - | 8,06-9,98% mỗi detector | Contamination **0,06/0,09**, không phải 0,01 (F8) |
| Checkpoint công bố | - | - | 8 lớp, d_model 400, decoder 400×400; Table III ghi 6 lớp, d=64 (F10) |

**Cơ chế chính: hướng gói tin mã hoá nhãn (F9).** Extractor của tác giả gán
`Direction='unknown'` cho mọi gói không thuộc đúng cặp attacker/victim trong cửa sổ tấn công
(tức toàn bộ benign). Bước dựng `pkt_vals` ghi mọi hướng khác `'fwd'` vào **nửa sau** của
block 50 chiều. Hệ quả: 25 chiều đầu của mọi block benign bằng 0, còn gói attack có fwd nằm
nửa trước. Một luật một bit "có byte khác 0 ở nửa trước" tách hai lớp gần như hoàn hảo mà
không cần graph, transformer hay học.

| Áp cách mã hoá benign của tác giả lên `P_paper` | Benign (FPR) | TPR mọi lớp |
|---|---:|---:|
| Luật 1 bit (fwd khác 0) | 0,0% | **100%** |
| OCSVM / INNE | 6,0 / 9,1% | 100% |
| IForest | 9,4% | 96,2-100% |
| Ensemble OR (HBOS suy biến ở pyod 3.6.7) | 17,7% | **100%** |
| CSV của tác giả (để so) | 13,12% (8,06-9,98%) | 98,50-99,83% |

**Tái lập đúng Table VI.** Với ngưỡng bỏ phiếu >=3/4 trên cùng artifact:

| Protocol | FPR (3 seed) | TPR (3 seed) | Seed 0 |
|---|---:|---:|---:|
| `P_paper` | 5,44-5,62% | 95,58-99,04% | 99,04% @ 5,50% |
| `T` | 6,52-6,66% | 99,22-99,99% | **99,22% @ 6,66%** |
| Paper Table VI | 6,56% | 99,04% | - |

Đây là cấu hình duy nhất trong toàn bộ đồ án sinh ra đúng 99,04%, và nó đòi hỏi artifact
hướng. Table VI khớp luật **majority** (>=3/4) đúng như văn bản, còn Table VII khớp **OR**
của code (F1): hai bảng của bài báo dùng hai luật khác nhau, và CSV công khai (13,12%) là
kết quả của OR.

Với cách mã hoá nhất quán của nhóm (hướng = sender gói đầu, áp cho cả hai lớp), 99,98% flow
benign cũng có fwd, nên luật này không còn tín hiệu. Bảng đầy đủ: `results/direction_leak.csv`
và `results/direction_leak_votes.csv`.

**Các mức đo được khi mã hoá nhất quán** (p=8, threshold đặt để FPR benign test = 6,56%):

| Cấu hình | Split | Đầu vào detector | TPR @ 6,56% | AUROC |
|---|---|---|---:|---:|
| `P_paper` GTAE của nhóm | same-day (Friday 70/30) | bottleneck `z` | 3,25% | 0,478 |
| `P_paper` raw | same-day | 400 byte thô | 3,25% | 0,402 |
| `P_paper` decoder output | same-day | recon 400-d | 4,93% | 0,452 |
| `T` GTAE của nhóm | temporal (Mon -> Tue-Fri) | bottleneck `z` | 11,54% | 0,594 |
| `T` raw | temporal | 400 byte thô | 18,78% | 0,698 |
| Supervised RF, same-day | Friday 70/30 | 400 byte thô | **99,9%** | 0,999 |
| Supervised RF, cross-day | Tue+Wed -> Thu+Fri | 400 byte thô | 3,2-3,8% | 0,54 |
| Supervised RF, cross-day | Tue+Wed -> Thu+Fri | `z` | 11,0-23,2% | 0,64-0,75 |

Hai quan sát quyết định. Thứ nhất, **cùng split same-day, chỉ classifier giám sát trên byte
thô đạt 99,9%**; GTAE same-day chỉ 3,25% với `z` và 4,93% với decoder output - split một mình
không tạo ra 99%. Thứ hai, **mọi cấu hình cross-day đều dừng ở <= 23,2% TPR @ 6,56%** (cao
nhất: supervised RF trên `z` 23,2%; raw OD 18,78%); không cấu hình nào tiến gần 99%, tức trần
đến từ feature/dữ liệu chứ không từ optimizer.

**Điều kiện để "giống".** Muốn đạt 99% phải đồng thời: (i) gán hướng benign khác attack
(F9); (ii) chia benign train/test cùng ngày (F4); (iii) dùng contamination 0,06/0,09 (F8);
(iv) báo FPR 6,56% dù artefact cho 13,12% (F2); (v) chạy một lớp mô hình mà code công bố
không khởi tạo được (F6/F10). Đó là tái lập **lỗi**, không phải tái lập phương pháp. Vì vậy
báo cáo giữ 99% như một artefact đã truy vết, không phải mục tiêu cần khớp.

---

## CHƯƠNG 6: SO SÁNH VỚI CÁC NGHIÊN CỨU LIÊN QUAN VÀ ĐÁNH GIÁ ƯU/NHƯỢC ĐIỂM

Chi tiết 12 bài liên quan và số công bố: Phụ lục B.

### 6.1 Định vị GTAE-IDS giữa các hướng tiếp cận

| Bài | Đầu vào | Đồ thị | Học | Phát hiện sớm | Zero-day | Điểm khác chính so với GTAE |
|---|---|---|---|---|---|---|
| **GTAE-IDS [1]** | 25 byte header × p gói | Có (nút IP:port) | One-class AE + 4 detector | Có | Có | - |
| SPIN-IDS [2] | Header + payload, ảnh 2D | Không | Supervised CNN | Có (4-9 gói) | Không | Cùng tác giả; cần nhãn |
| PBCNN [4] | Byte thô của cả luồng | Không | Supervised CNN | Hạn chế | Không | Cần cả luồng |
| E-GraphSAGE [6] | NetFlow | Có | Supervised | Không | Không | Mean aggregation thay attention |
| Anomal-E [8] | NetFlow | Có (nút = IP) | Self-supervised DGI + detector | Không | Có | Cùng mô hình "GNN → detector cổ điển"; báo cả F1 |
| GraphIDS [10] | NetFlow | Có | GNN + Transformer MAE, end-to-end | Không | Có | Học biểu diễn và phát hiện trong một mục tiêu |
| Kitsune [11] | Thống kê theo gói | Không | Ensemble AE online | Có (theo gói) | Có | Streaming thật sự, chạy trên thiết bị nhẹ |

**Nhận xét:** GTAE là bài duy nhất trong nhóm kết hợp cả ba yếu tố (packet-level, đồ thị, không giám sát). Đây là điểm mới thật sự của bài báo. Đổi lại, nó không có baseline nào được đo trong cùng điều kiện: Table XI-XIII của bài báo so với các phương pháp supervised hoặc flow-based, trên tập chia cân bằng.

### 6.2 So sánh cùng protocol (nhóm tự cài đặt và đo)
Cùng dữ liệu (protocol `T`), cùng mã hoá 25 byte, cùng 4 detector, p = 8, mean ± std 3 seed (Phụ lục E.1):

| Phương pháp | Đại diện cho | TPR | FPR | AUROC | TPR@FPR=1%* |
|---|---|---:|---:|---:|---:|
| M1 GTAE (attention + LapPE) | [1] | 4,18 ± 4,30% | 2,79 ± 1,40% | 0,594 ± 0,106 | 3,65 ± 4,48% |
| **B2 E-GraphSAGE-AE** (mean aggregation, cùng độ sâu/độ rộng) | [6], encoder của [8] | **9,78 ± 9,76%** | 1,81 ± 1,72% | **0,689 ± 0,021** | **11,30 ± 10,52%** |
| **A2 GTAE bỏ LapPE** | ablation | 6,36 ± 3,72% | 1,23 ± 0,68% | **0,682 ± 0,003** | **12,46 ± 0,86%** |
| B1 MLP-AE (không đồ thị) | AE trong [11] | 6,29 ± 1,10% | 2,29 ± 0,17% | 0,595 ± 0,005 | 6,95 ± 1,70% |
| B0 vector thô (không học biểu diễn) | [4], [5] bản không giám sát | 0,50 ± 0,36% | 1,22 ± 0,05% | 0,698 ± 0,004 | 2,13 ± 0,25% |
| B0, chỉ HBOS | - | 0,00% | 1,66% | **0,810 ± 0,000** | 0,00% |
| A3 GTAE + reconstruction MSE | mục tiêu của [10] | 6,01 ± 9,69% | 2,07 ± 1,34% | 0,649 ± 0,012 | 6,01% |

\* Ngưỡng là quantile 99% của điểm trên `train2` (benign Monday). FPR thực trên benign test được ghi ở Phụ lục E.1 và thường > 1% do dịch chuyển phân phối.

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
| 25 byte không chứa IP/port; tín hiệu **không phụ thuộc** TTL/checksum (A5 zero hoá rồi train lại: AUROC 0,594 -> 0,675) | test chống rò rỉ; A5 |
| Kiến trúc cài đặt được, kích thước nhỏ (p = 8: d = 64) | [src/model_gtae.py](https://github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS/blob/main/src/model_gtae.py) |
| Cho phép quyết định theo p gói (khung cho phát hiện sớm) | P1 (Chương 7) |

**Nhược điểm (có số đo)**

| Nhược điểm | Bằng chứng |
|---|---|
| Embedding tách benign/attack kém khi có dịch chuyển phân phối theo thời gian (AUROC ~0,6) | §4.1 |
| Huấn luyện không ổn định theo seed (AUROC 0,495-0,705) | Phụ lục E.1 |
| Attention và LapPE không mang lại lợi ích; còn làm kém và bất ổn hơn | B2, A2 (§6.2) |
| Đồ thị tĩnh theo cửa sổ: phải dựng lại line graph, nên không đạt thời gian thực | §4.5 |
| Ensemble 4 detector bằng phiếu cứng: không kiểm soát được FPR | §4.3; F1, F2 |
| Đánh giá trong bài báo: tập test toàn tấn công, đồ thị riêng từng lớp, benign cùng ngày | F3, F4; §4.4 |

---

## CHƯƠNG 7: ĐỀ XUẤT CẢI TIẾN

### 7.1 Chẩn đoán làm cơ sở cho đề xuất
Từ Chương 4-6, GTAE-IDS có hai điểm yếu nằm ở **hai tầng khác nhau**:
1. **Tầng biểu diễn:** embedding tách benign/attack kém và bất ổn theo seed. Attention và LapPE không giúp ích.
2. **Tầng quyết định:** phiếu cứng của 4 detector không cho phép chọn và **bảo đảm** FPR, và luôn phải chờ đủ p gói.

Đề xuất của nhóm giải quyết lần lượt từng tầng.

**Đã thử đổi kiến trúc trước khi đề xuất.** Nhóm không suy đoán: các biến thể đã được
train cùng protocol `T`, cùng p = 8, 3 seed:

| Biến thể | Thay đổi | AUROC | TPR @FPR 6,56% | TPR @FPR 1% |
|---|---|---:|---:|---:|
| M1 | attention + LapPE | 0,594 | 11,54% | 3,65% |
| A2 | bỏ LapPE | 0,676 | 15,53% | 6,37% |
| B2 | mean aggregation thay attention | **0,689** | **16,27%** | **6,40%** |
| B0 | không học gì (raw 400-d) | **0,698** | **18,78%** | 2,13% |
| B1 | MLP-AE, không đồ thị | 0,595 | - | 6,95% |
| A3 | reconstruction error thay detector | 0,649 | - | 6,01% |

Toàn bộ họ kiến trúc nằm trong **0,59-0,70 AUROC** và **11,5-18,8% TPR** ở cùng FPR; biến
thể tốt nhất hơn M1 +0,095 AUROC, nhưng **B0 không học còn cao hơn**. Đổi attention, PE, độ
sâu hay thêm tham số chỉ dịch kết quả trong khoảng ~0,1 AUROC; không có biến thể nào tiến
gần 0,8. Nút thắt là thông tin trong 25 byte header và dịch chuyển benign theo ngày, không
phải kiến trúc. Vì vậy Đề xuất A chọn **đơn giản hoá và ổn định hoá** thay vì thêm tầng.

### 7.2 Đề xuất A (tầng biểu diễn): bộ mã hoá gọn hơn
**Nội dung:** thay attention giữa các cạnh bằng **mean aggregation** (E-GraphSAGE-AE, giữ nguyên độ sâu và độ rộng của `ARCH[p]`) và **bỏ LapPE**.

**Lý do:**
- Attention với softmax trên lân cận line graph có phương sai cao khi hub có bậc lớn (K_max = 32).
- LapPE có mơ hồ về dấu và phụ thuộc thành phần liên thông, nên thay đổi giữa đồ thị train và test.
- Mean aggregation và không dùng PE cho biểu diễn ổn định hơn với phân phối dịch chuyển.

**Kết quả đo (p = 8, protocol `T`, 3 seed):**

| | M1 (gốc) | A: bỏ LapPE | A: mean aggregation (B2) |
|---|---:|---:|---:|
| AUROC | 0,594 ± 0,106 | **0,682 ± 0,003** | **0,689 ± 0,021** |
| TPR @ ngưỡng FPR=1% | 3,65 ± 4,48% | **12,46 ± 0,86%** | **11,30 ± 10,52%** |
| TPR @ FPR 6,56% (quantile benign test) | 11,54% | **15,53%** | **16,27%** (11,0-25,8 theo seed) |
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

**7.3.3 Kết quả (T_fixed, mean ± std 3 seed; `P1.md`)**

| α | Fusion | TPR | FPR thực đo | Số gói TB đến quyết định (attack) | Tỉ lệ dừng sớm (attack) | AUROC |
|---|---|---:|---:|---:|---:|---:|
| 0,05 | **Bonferroni** | **8,95 ± 3,72%** | **3,64 ± 1,00%** (≤ 5%) | 7,75 | 7,70% | 0,662 ± 0,021 |
| 0,10 | **Bonferroni** | **14,11 ± 2,11%** | **5,78 ± 1,35%** (≤ 10%) | 7,56 | 13,22% | 0,662 ± 0,021 |
| 0,01 | Bonferroni | 0% | 0% | 8,00 | 0% | 0,662 |
| 0,05 | Fisher (exploratory) | 47,53 ± 4,23% | 18,86 ± 4,81% (> α) | 6,24 | 46,98% | 0,639 |

**Đánh giá trung thực:**
1. **Đạt:** Bonferroni giữ FPR thực đo ≤ α ở cả α = 0,05 và α = 0,10, trên benign của **ngày khác** với calibration. Đây là thứ phiếu cứng của bài báo không làm được: người vận hành chọn trước mức báo động giả chấp nhận được.
2. **Hạn chế về lý thuyết:** calibration (Monday) và benign test (Tue-Fri) không exchangeable, nên "FPR ≤ α" ở đây là **quan sát thực nghiệm**, không còn là bảo đảm lý thuyết.
3. **Hạn chế về hiệu quả:** AUROC chỉ tăng từ 0,594 lên 0,662; TPR@FPR=1% của Bonferroni là 0%, thấp hơn M1 (3,65%). Phát hiện sớm có tác dụng nhỏ (số gói trung bình 7,56-7,75 so với 8).
4. **Fisher** cho TPR cao nhưng FPR vượt α do 4 detector tương quan. Không dùng để khẳng định kiểm soát FPR.
5. **Chi phí:** cần chạy 7 mô hình (mỗi p một mô hình); early-exit không giảm chi phí dựng đồ thị (§4.5).

### 7.4 Kết hợp A + B và các bước tiếp theo
Đề xuất B chỉ thay tầng quyết định nên bị giới hạn bởi chất lượng embedding (AUROC ~0,6). Kết
hợp với Đề xuất A là bước hợp lý tiếp theo, nay đã đo: P1 chạy trên encoder B2 với các bước
p = 2, 4, 8, đối chứng P1 trên GTAE cùng bước (`results/P1_egsage/`, `results/P1_p248/`):

| Cấu hình (3 bước p=2/4/8) | α | TPR | FPR | APD attack | Early-exit | AUROC fusion | TPR@FPR=1% |
|---|---:|---:|---:|---:|---:|---:|---:|
| M1 + P1 | 0,05 | 12,13% | 5,17% | 7,57 | 10,4% | 0,604 | 0,00% |
| M1 + P1 | 0,10 | 19,40% | 7,53% | 7,34 | 15,9% | 0,604 | 0,00% |
| **B2 + P1** | 0,05 | **14,49%** | **4,76%** | 7,72 | 5,9% | **0,662** | 0,00% |
| **B2 + P1** | 0,10 | **18,52%** | 6,93% | 7,59 | 8,4% | **0,662** | 0,00% |

Bảng này dùng 3 bước (2, 4, 8), khác bảng 7 bước ở §7.3; ít bước hơn nên ngưỡng Bonferroni
dễ đạt hơn, vì vậy chỉ so trong cùng bảng.

**Đánh giá A+B:** đây là cấu hình sạch tốt nhất ở vùng FPR trung bình (14,5% @ 4,8%; 18,5%
@ 6,9%), nhưng so với B đơn lẻ (M1+P1) chỉ hơn 2,4 pp ở α=0,05 và gần hòa ở α=0,10 - lợi thế
encoder bị fusion conformal san phẳng. Tại FPR=1% cả hai đều 0%, thấp hơn M1 (3,65%). Trần
của biểu diễn vẫn ~0,7 AUROC; B0 raw (không học) đạt 18,78% @ 6,56, tương đương A+B, nên cải
thiện kiến trúc không phải nút thắt.

Các hướng khác đã cân nhắc, xếp theo mức độ nhắm vào điểm nghẽn biểu diễn:
- **P4 - nút = IP, có/không node features (ablation 2 bước, theo Anomal-E [8]):**
  - **P4a (chỉ đổi khoá nút):** `(IP, port)` -> `IP`, giữ nguyên mô hình/edge feature. Hai luồng
    cùng một host nhưng khác port tạm trước đây không kề nhau, nay dùng chung nút; PortScan
    6.451 luồng tới 6.451 port đích trước đây tạo 6.451 nút, nay dồn về một hub nạn nhân.
    Đây là phép thử sạch nhất cho giả thuyết "phân mảnh đồ thị do port".
  - **P4b (thêm node features):** vector label-free cho mỗi IP: in/out degree, số luồng, số port
    đích, byte/gói trung bình, thời lượng; chiếu vào `d` rồi cộng vào biểu diễn cạnh ở hai đầu.
  - **Cổng quyết định (đặt trước):** chỉ làm P4b nếu P4a tăng >= 0,03 AUROC **và** >= 2 pp
    TPR@FPR=1% so với B2 (0,689 / 6,40%), đồng thời không giảm TPR@6,56%; nếu không, dừng và
    ghi nhận kết quả âm. Chi phí P4a: dựng lại graph p=8 + train 3 seed (~30-60 phút), không
    cần dữ liệu hay kiến trúc mới.
- **P5 - mục tiêu masked reconstruction** (GraphMAE [14]): buộc mô hình dùng ngữ cảnh thay vì sao chép đặc trưng cạnh.
- **Online conformal / calibration theo cửa sổ trượt:** khôi phục giả định exchangeable khi phân phối trôi theo thời gian.

---

## CHƯƠNG 8: KẾT LUẬN

1. **Tìm hiểu bài báo:** nhóm phân tích đầy đủ phương pháp, cài đặt đúng Table III/V và Fig. 3/4, và liệt kê những điểm bài báo không mô tả nhưng ảnh hưởng tới khả năng tái lập (§2.5).
2. **Tái hiện:** pipeline hoàn chỉnh từ pcap, 132 test, 428 kiểm tra artefact, 4 protocol. Con số 99,04% **không tái lập được bằng cài đặt đúng** (kể cả `P_paper`: 3,25% @ 6,56%); nó **chỉ tái lập được khi tái tạo artifact mã hoá hướng** của tác giả (trên `T`: 99,22% @ 6,66% FPR, seed 0; 99,22-99,99% qua 3 seed). Nhóm báo cáo phương sai giữa các seed và các tiêu chí không đạt.
3. **Đối chiếu và so sánh:**
   - Nhóm kiểm chứng được các mâu thuẫn giữa bài báo, code và CSV của tác giả (luật OR, FPR không khớp, contamination 0,06/0,09, test theo từng lớp, notebook không chạy được).
   - **Nguyên nhân chính của 99% đã được truy vết**: hướng gói tin benign bị gán `unknown` và dồn vào nửa sau, tạo ra một luật 1 bit TPR 100% / FPR 0%; tái tạo đúng cách mã hoá đó trên `P_paper` cho 100% TPR @ 17,7% FPR, khớp CSV tác giả (98,5-99,8% @ 13,12%).
   - Baseline cùng protocol cho thấy attention, LapPE và ngữ cảnh đồ thị đều không phải nguồn tín hiệu.
   - Claim "real-time" không đúng ở mức triển khai.
4. **Đề xuất:**
   - (A) Mean aggregation / bỏ LapPE: AUROC +0,09 (0,594 -> 0,689), ổn định hơn 5-38 lần, TPR@FPR=1% gấp khoảng 3 lần, TPR@FPR=6,56% tăng 11,54 -> 16,27% (+41%).
   - (B) Conformal early-exit: FPR thực đo ≤ α nhưng TPR tăng ít; tại FPR=1% bằng 0.
   - (A+B) B2 + P1: 14,49% @ 4,76% và 18,52% @ 6,93% - tốt nhất ở FPR trung bình, nhưng vẫn 0% tại FPR=1% và chỉ hơn B đơn lẻ 2,4 pp.
   - Đánh giá thẳng: cải thiện **trung bình**, không đột phá; trần biểu diễn ~0,7 AUROC. Muốn vượt cần thêm thông tin (payload/flow stats) hoặc đổi protocol, không phải tinh chỉnh kiến trúc.

---

## PHỤ LỤC A - TÁI LẬP KẾT QUẢ

Các lệnh dưới chạy từ gốc repo (địa chỉ GitHub ở trang bìa) với `.venv/bin/python`; mọi bảng số liệu trong báo cáo đã bao gồm các kết quả này.

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

## PHỤ LỤC B - SỐ LIỆU CÔNG TRÌNH LIÊN QUAN (CHI TIẾT)

### B.1 GNN giám sát flow-based (Table XI của bài neo)

| Method | Slowloris | Hulk | GoldenEye | Heartbleed | WebBF | DDoS |
|---|---:|---:|---:|---:|---:|---:|
| E-GraphSAGE | 0,973 | 0,989 | 0,992 | 0,983 | 0,954 | 0,965 |
| E-ResGAT / GNN (Pujol-Perich) | 0,982 | 0,993 | 0,991 | 0,978 | **0,734** | 0,991 |
| GraphDDoS | 0,967 | 0,993 | 0,978 | 0,981 | 0,967 | 0,983 |
| GTAE-IDS | 0,996 | 0,988 | 0,991 | 0,996 | 0,993 | 0,994 |

Đã đối chiếu PDF gốc: dòng **E-GraphSAGE** không có trong bài gốc (bài gốc đánh giá
NF-UNSW-NB15/NF-ToN-IoT/NF-BoT-IoT, metric F1/FAR, không có CIC-IDS2017 hay TPR từng lớp);
dòng **Pujol-Perich** khớp Bảng 1 của bài gốc (accuracy từng lớp, Web-BF 0,73), nhưng bài gốc
không có Heartbleed/Infiltration và đã bỏ 90% graph benign trước khi đánh giá. GraphDDoS là
nguồn thứ cấp (paywall).

### B.2 Packet-based không đồ thị (Table XII của bài neo)

| Method | TPR | µs/gói |
|---|---:|---:|
| PL-RNN | 0,564 | 2,91 |
| Packet2Vec | 0,728 | 3,54 |
| HAST-II | 0,690 | 4,2 |
| AEIDS | 0,587 | 2,65 |
| PayloadEmbeddings | 0,954 | 2,73 |
| PBCNN | 0,983 | 7,89 |
| GTAE-IDS | 0,990 | 1,28 |

### B.3 SPIN-IDS và đường cong theo p (Table XIII của bài neo)

| p | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|
| SPIN-IDS (supervised, có payload) | 81,59 | 86,50 | 92,02 | 94,47 | 97,54 | 97,54 | 98,77 |
| GTAE-IDS | 84,47 | 91,02 | 94,72 | 97,16 | 98,44 | 98,72 | 99,04 |
| Nhóm, protocol `T` (7 seed) | 2,99 | 7,31 | 9,29 | 8,82 | 9,21 | 4,43 | 7,63 |

### B.4 Các bài khác

| Paper | Số công bố | Điều kiện |
|---|---|---|
| Anomal-E | HBOS trên CSE-CIC-IDS2018: macro-F1 **86,28 -> 94,51** khi dùng embedding | NetFlow, self-supervised, contamination 0% (đã kiểm chứng Bảng 5 của bài gốc) |
| GraphIDS | PR-AUC tới **99,98%**, macro-F1 tới **99,61%** | NetFlow benchmarks, self-supervised |
| Kitsune | TPR/FPR/AUC trên mạng camera IoT tự dựng | packet-streaming, unsupervised (không trích số cụ thể) |

### B.5 Kết quả đối chiếu PDF gốc

| Số trong bài neo | Bài gốc | Kết luận |
|---|---|---|
| Table XI, dòng E-GraphSAGE | arXiv:2103.16329, 9 trang | **Không có trong bài gốc** |
| Table XI, dòng Pujol-Perich | arXiv:2107.14756, Bảng 1 | Khớp một phần (accuracy, thiếu 2 lớp) |
| Anomal-E 86,28 -> 94,51 | arXiv:2207.06819, Bảng 5 | **Khớp chính xác** |
| PBCNN, SPIN-IDS, GraphDDoS, GraphIDS | paywall / không tìm thấy PDF | Nguồn thứ cấp |

## PHỤ LỤC C - BASELINE VÀ ABLATION (CHI TIẾT)

### C.1 Kết quả p = 8 (mean 3 seed, protocol `T`)

| Phương pháp | TPR | FPR | AUROC | TPR@FPR=1% |
|---|---:|---:|---:|---:|
| M1 GTAE (ensemble tie) | 4,18% | 2,79% | 0,594 | 3,65% |
| A3 reconstruction-error | 6,01% | 2,07% | 0,649 | 6,01% |
| B0 raw vector (tie) | 0,50% | 1,22% | **0,698** | 2,13% |
| B0 raw vector (HBOS) | 0,00% | 1,66% | **0,810** | 0,00% |
| B1 MLP-AE (tie) | 6,29% | 2,29% | 0,595 | 6,95% |
| B2 E-GraphSAGE-AE (tie) | **9,78%** | 1,81% | 0,689 | 11,30% |
| A2 bỏ LapPE (tie) | 6,36% | 1,23% | 0,682 | 12,46% |
| A5 header hygiene (tie) | 2,83% | 2,33% | 0,675 | 3,77% |

### C.2 A3 theo p

| p | M1 TPR/FPR | A3 TPR/FPR | A3 AUROC | ΔTPR |
|---:|---|---|---:|---:|
| 2 | 3,30% / 2,89% | 6,23% / 6,31% | 0,425 | +2,92 pp |
| 4 | 8,56% / 2,94% | 12,15% / 3,51% | 0,519 | +3,59 pp |
| 8 | 4,18% / 2,79% | 6,01% / 2,07% | 0,649 | +1,82 pp |

### C.3 A5 theo detector (p = 8)

| Detector | M1 AUROC | A5 AUROC | ΔAUROC | M1 TPR@1% | A5 TPR@1% |
|---|---:|---:|---:|---:|---:|
| IForest | 0,601 | 0,677 | +0,076 | 3,12% | 3,16% |
| OCSVM | 0,595 | 0,672 | +0,077 | 0,10% | 2,40% |
| HBOS | 0,543 | 0,673 | +0,130 | 7,35% | 2,96% |
| INNE | 0,578 | 0,636 | +0,058 | 4,80% | 0,84% |

### C.4 Ghi chú HBOS

HBOS được ghi nhận khi cột embedding quá thưa để chia bin; hai lần chạy (A5 p8 seed0, M1 p8
seed2) phải hạ `n_bins` xuống 3. Khi so sánh các lần chạy, kiểm tra ghi chú này trước vì
`n_bins` khác làm HBOS (và ensemble có HBOS) không so sánh trực tiếp được.

## PHỤ LỤC D - P1 (CHI TIẾT)

| α | Fusion | TPR | FPR | APD attack | APD benign | Early-exit attack | AUROC | TPR@FPR=1% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0,01 | Bonferroni | 0,00% | 0,00% | 8,00 | 8,00 | 0,00% | 0,662 | 0,00% |
| 0,05 | Bonferroni | 8,95% | 3,64% | 7,75 | 7,91 | 7,70% | 0,662 | 0,00% |
| 0,10 | Bonferroni | 14,11% | 5,78% | 7,56 | 7,84 | 13,22% | 0,662 | 0,00% |
| 0,01 | Fisher | 42,46% | 13,57% | 6,44 | 7,41 | 41,57% | 0,639 | 2,77% |
| 0,05 | Fisher | 47,53% | 18,86% | 6,24 | 7,23 | 46,98% | 0,639 | 2,77% |
| 0,10 | Fisher | 49,33% | 22,96% | 6,16 | 7,08 | 48,58% | 0,639 | 2,77% |

Calibration 40% của `train2` (800 flow), detector fit trên 1.200 flow còn lại, mean 3 seed.
Bonferroni giữ FPR thực đo <= α nhưng TPR tăng ít; Fisher vượt α do 4 detector tương quan.

## PHỤ LỤC E - SỐ LIỆU BỔ SUNG

### E.1 Phương sai theo seed (p = 8, protocol `T`)

| Phương pháp | n | TPR (%) | FPR (%) | AUROC |
|---|---:|---:|---:|---:|
| M1 GTAE (tie) | 3 | 4,18 ± 4,30 | 2,79 ± 1,40 | 0,594 ± 0,106 [0,495-0,705] |
| M1 GTAE (tie, 7 seed) | 7 | 7,63 ± 6,56 | 2,53 ± 1,13 | 0,663 ± 0,092 [0,495-0,750] |
| B0 raw vector (tie) | 3 | 0,50 ± 0,36 | 1,22 ± 0,05 | 0,698 ± 0,004 |
| B0 raw vector (HBOS) | 3 | 0,00 ± 0,00 | 1,66 ± 0,14 | 0,810 ± 0,000 |
| B1 MLP-AE (tie) | 3 | 6,29 ± 1,10 | 2,29 ± 0,17 | 0,595 ± 0,005 |
| B2 E-GraphSAGE-AE (tie) | 3 | 9,78 ± 9,76 | 1,81 ± 1,72 | 0,689 ± 0,021 |
| A2 bỏ LapPE (tie) | 3 | 6,36 ± 3,72 | 1,23 ± 0,68 | 0,682 ± 0,003 |
| A5 header hygiene (tie) | 3 | 2,83 ± 2,34 | 2,33 ± 1,76 | 0,675 ± 0,042 |

### E.2 `P_paper`: so với Table II (nút, cạnh)

| p | test edge của paper | test edge của nhóm | test node của paper | test node của nhóm |
|---:|---:|---:|---:|---:|
| 2 | 38.984 | 30.041 | 44.767 | 22.328 |
| 4 | 36.964 | 30.041 | 45.008 | 22.328 |
| 6 | 35.482 | 30.041 | 43.417 | 22.328 |
| 8 | 33.228 | 30.041 | 40.744 | 22.328 |

train1 = 5.000 edge / 7.178 node, train2 = 2.000 / 3.105, gần paper (7.023 / 3.106 ở p=8).
Hai khác biệt: (i) nhóm zero-pad flow ngắn nên số cạnh test không đổi theo p, còn paper dựng
lại tập test theo từng p với điều kiện `n_pkts >= p`; (ii) node test của nhóm ít hơn vì cùng
một endpoint dịch vụ lặp lại trên nhiều luồng. Heartbleed/Infiltration không đủ dòng CSV
(11 và 34) nên không thể đạt 1.468/1.764 cạnh của paper.

### E.3 Per-class p = 8 so với Table VII của paper

| Lớp | Paper | `P_paper` (OR) | `P_paper` (tie) |
|---|---:|---:|---:|
| DDoS | 99,34% | 9,23% | 0,61% |
| DoS GoldenEye | 99,08% | 7,65% | 0,75% |
| DoS Hulk | 98,74% | 7,57% | 0,58% |
| DoS Slowhttptest | 99,79% | 6,43% | 0,76% |
| DoS Slowloris | 99,60% | 8,55% | 2,00% |
| FTP-Patator | 98,85% | 6,32% | 1,72% |
| Heartbleed | 99,52% | 33,33% | 0,00% |
| Infiltration | 99,83% | 0,98% | 0,98% |
| PortScan | 98,50% | 28,56% | 25,31% |
| SSH-Patator | 98,86% | 5,52% | 0,19% |
| Web Attack - Brute Force | 99,29% | 5,71% | 0,48% |

### E.4 Chuyển miền: CIC-IDS2018 và ACI-IoT-2023

| Bộ | Detector | TPR | FPR | AUROC | TPR@1% |
|---|---|---:|---:|---:|---:|
| 2018 | IForest | 5,15% | 1,29% | 0,762 | 6,01% |
| 2018 | OCSVM | 5,66% | 1,21% | 0,683 | 6,15% |
| 2018 | HBOS | 6,57% | 1,61% | 0,767 | 6,01% |
| 2018 | INNE | 16,69% | 6,15% | 0,812 | 19,53% |
| 2018 | Ensemble tie | 5,99% | 1,52% | 0,764 | 5,94% |
| ACI (p = 8) | Ensemble tie | 1,69% | 1,11% | 0,536 | 1,95% |

ACI theo p (ensemble tie): TPR 2,68 / 1,23 / 1,78 / 1,65 / 2,40 / 1,76 / 1,69% và AUROC
0,564 / 0,428 / 0,477 / 0,483 / 0,536 / 0,550 / 0,536 cho p = 2..8. ACI per-class p=8:
PortScan 2,66%, Slowloris 1,76%, Dictionary Brute Force 0,66% (paper Table IX: 99,67 / 99,56 /
không có lớp này).

### E.5 Độ trễ và thời gian chờ

| Stage | mean (µs/flow) | p50 | p95 |
|---|---:|---:|---:|
| graph | 115,1 | 64,7 | 493,6 |
| line graph | 72.389,1 | 6.263,0 | 448.377,4 |
| PE | 0,3 | 0,2 | 0,6 |
| forward | 13.298,5 | 2.759,0 | 90.746,6 |
| detector | 36.344,5 | 36.022,8 | 39.336,0 |
| **total** | **122.177,8** | 47.975,2 | 488.013,6 |

Replay Friday: 349.256 flow, 512,6 flow/s replay, **8,2 flow/s detect** so với 12,1 flow/s lưu
lượng đến; 3.116/3.492 flow đo là `stale` (đóng ở biên capture). Thời gian chờ đủ p gói
(wait_p, protocol `T`): median delay 0,036 / 0,051 / 0,101 / 0,132 s cho p = 2/4/6/8 ở benign;
0,000 / 0,008 / 0,079 / 0,079 s ở attack, p95 = 3,79 s. Theo lớp ở p=8: Slowhttptest 63,1 s
(p95 218 s), slowloris 3,0 s (p95 46,5 s), GoldenEye 6,27 s, PortScan chỉ 0,1% flow đạt 8 gói.

## PHỤ LỤC F - CHI TIẾT ĐỐI CHIẾU MÃ NGUỒN (F1-F10)

### F.1 (F1) Table VII trùng khớp output của luật OR

| Lớp (repo `Final_Results_8pkt_Anomaly_Detection_2017.csv`) | Ensemble | Paper Table VII |
|---|---:|---:|
| DoS GoldenEye | 99,08 | 99,08 |
| Heartbleed | 99,52 | 99,52 |
| DoS Slowhttptest | 99,79 | 99,79 |
| DoS Slowloris | 99,60 | 99,60 |
| DoS Hulk | 98,74 | 98,74 |
| PortScan | 98,50 | 98,50 |
| DDoS | 99,34 | 99,34 |
| Infiltration | 99,83 | 99,83 |
| Web Attack-BruteForce | 99,29 | 99,29 |
| SSH-Patator | 98,86 | 98,86 |
| FTP-Patator | 98,85 | 98,85 |

Số node/edge trong cùng CSV cũng trùng Table VII (6.090; 1.468; 964; 1.002; 5.000; 6.451;
5.000; 1.764; 140; 175; 174). Code vote trong `GTAE_8pkt.ipynb` là
`votes = np.sum(prediction == 1 ...); anomalies_ensemble = (votes >= 1)`, tức OR.

### F.2 (F2) Điểm vận hành công bố không khớp CSV

| | OCSVM | IForest | HBOS | INNE | Ensemble |
|---|---:|---:|---:|---:|---:|
| Paper Table VI (FPR) | 4,03 | 4,93 | 4,96 | 4,99 | **6,56** |
| CSV công khai (Benign) | 8,06 | 9,86 | 9,92 | 9,98 | **13,12** |

### F.3 (F3) Đồ thị per-class: đã định lượng

Dựng lại đúng kiểu paper trên `P_paper` p8 (mỗi lớp một đồ thị chỉ-tấn-công, cùng encoder,
ngưỡng từ calibration benign): TPR trên đồ thị riêng không cao hơn đồ thị trộn (PortScan
0,00% vs 6,32%; DoS Hulk 0,07% vs 0,15%; Infiltration 0,98% vs 0,00%; mọi lớp <= 0,98%).
Topo chỉ-attack không phải lối tắt mà mô hình của nhóm khai thác được.

### F.4 (F5, F6) Detector chạy trên output decoder; lớp công khai không nối encoder

`GTAE_8pkt.ipynb` gọi `autoencoder(test_graph, features)` và nhận `decoded_features` (400
chiều), không phải embedding bottleneck như paper mô tả. Lớp `GraphAutoencoder` trong
notebook dùng `self.decoder(features)` và bỏ qua `edge_features`; ô đó không khởi tạo được
như hiện có.

### F.5 (F7) Trượt hàng nhãn: đã định lượng

Trên Thứ Ba: 851.306 gói, 269.201 gói nền trong cửa sổ bị bỏ qua, 80.848 gói (13,9%) sai
nhãn; precision nhãn tấn công 11,8%, recall 14,8%; 15.893 flow (14,4%) bị ảnh hưởng.

### F.6 (F8) Contamination thực trong code

Cell 55-59 dùng `OCSVM(nu=0.05, contamination=0.06)` và `IForest/HBOS/INNE(contamination=0.09)`,
không phải 0,01 như Table V. Với 0,09, mỗi detector tự gán ~9-10% benign train là outlier,
nên FPR benign test ~9-10%, đúng cột Benign của CSV. Đây là lời giải thích đầy đủ cho F2.

### F.7 (F9) Hướng gói tin: benign `unknown` -> nửa sau

Extractor gán `'unknown'` cho mọi gói không thuộc cặp attacker/victim trong cửa sổ; bước dựng
`pkt_vals` ghi mọi hướng khác `'fwd'` vào nửa sau. Vì vậy 25 chiều đầu của mọi block benign
bằng 0, còn attack có fwd. Tái tạo trên `P_paper` (`results/direction_leak.csv`):

| | Benign FPR | TPR (mọi lớp) |
|---|---:|---:|
| Luật 1 bit "fwd khác 0" | 0,0% | 100% |
| OCSVM / INNE | 6,0 / 9,1% | 100% |
| IForest | 9,4% | 96,2-100% |
| Ensemble OR | 17,7% | 100% |
| CSV tác giả | 13,12% (8,06-9,98%) | 98,50-99,83% |

Với mã hoá nhất quán của nhóm, 99,98% benign cũng có fwd, nên luật này không còn tín hiệu.

### F.8 (F10) Checkpoint công bố

8 lớp `nn.TransformerEncoderLayer`, `d_model=400`, FFN 64, decoder 400×400; Table III ghi
6 lớp, d=64. Chạy checkpoint trên feature `P_paper` (cùng semantics), scaler trên `train1`,
contamination 0,06/0,09: FPR ensemble 19,5%; TPR theo lớp 2,9-81,8% - không tái tạo CSV.


## PHỤ LỤC G - ĐỐI CHIẾU BỐN YÊU CẦU CỦA ĐỒ ÁN

| # | Yêu cầu | Trạng thái | Bằng chứng |
|---|---|---|---|
| 1 | Tìm hiểu vấn đề và phương pháp của bài báo | Đầy đủ | Ch.1 (bài toán, động cơ, câu hỏi nghiên cứu); Ch.2 (feature 25 byte, graph, encoder eq. 2-8, detector, Table III/V); §2.5 (các giả định) |
| 2 | Thực hiện phương pháp và đánh giá kết quả | Đầy đủ | Ch.3 (pipeline 51 GB, 132 test, 428 audit); Ch.4 (T, P_paper, 2018, ACI, latency); Ch.5 (audit code); Phụ lục E |
| 2b | "Tái lập đúng số liệu paper" | **Có điều kiện** | 99,04% TPR tái lập **chỉ khi** tái tạo artifact hướng: trên `T`, >=3/4 cho **99,22% @ 6,66%** (seed 0; 99,22-99,99% @ 6,52-6,66% qua 3 seed) - trùng Table VI trong 0,2/0,1 pp. Cài đặt đúng Fig. 3: 3,25-18,78% @ 6,56%. Table VI khớp >=3/4, Table VII khớp OR; CSV tác giả 13,12% |
| 3 | So sánh, đánh giá ưu/nhược với bài khác | Đầy đủ | §6.1 (định vị 7 bài); §6.2 (cùng protocol); §6.3 (5 tuyên bố); §6.4 (cách so sánh); §6.5 (ưu/nhược); Phụ lục B (Table XI-XIII) |
| 4 | Đề xuất giải pháp cải thiện | Đầy đủ | Ch.7: A (B2/A2), B (P1), **A+B đã đo** (14,49% @4,76%; 18,52% @6,93%); mức cải thiện trung bình, trần ~0,7 AUROC |

**Kết luận:** cả bốn yêu cầu đã được thực hiện. Riêng yêu cầu "đúng số liệu paper" chỉ đạt
được ở dạng có điều kiện: 99,04% TPR tái lập được, nhưng phải tái tạo lỗi mã hoá hướng của
tác giả; FPR công bố 6,56% không khớp bất kỳ ngưỡng rời rạc nào, kể cả trên artifact
(5,4-8,9%), và CSV công khai của tác giả ghi 13,12%. Đây là kết luận của Chương 5, không
phải thiếu sót của phần thực hiện.
