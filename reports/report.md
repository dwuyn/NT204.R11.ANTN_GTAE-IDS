# BÁO CÁO NGHIÊN CỨU ĐỒ ÁN MÔN HỌC
## HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG THỜI GIAN THỰC DỰA TRÊN ĐỒ THỊ BIẾN ĐỔI TỰ MÃ HÓA (GTAE-IDS)
### TÁI HIỆN ĐỘC LẬP, PHẢN BIỆN MÃ NGUỒN GỐC VÀ ĐỀ XUẤT CẢI TIẾN P1 (CONFORMAL EARLY-EXIT)

---

**Môn học:** Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập (NT204.R11.ANTN)  
**Nhóm thực hiện:** Nhóm B  
**Thời gian hoàn thành:** 10/11/2026
**Bài báo nghiên cứu cơ sở (Paper neo):**  
> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026–4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

---

## TÓM TẮT ĐỒ ÁN (ABSTRACT)

Nghiên cứu này thực hiện quy trình tái hiện độc lập toàn diện và phản biện học thuật đối với khung làm việc **GTAE-IDS** (IEEE TIFS 2025) — một mô hình học không giám sát biểu diễn cấu trúc đồ thị luồng mạng cấp độ gói tin để phát hiện tấn công zero-day thời gian thực. Bằng việc xây dựng lại toàn bộ pipeline kỹ thuật sạch từ 51 GB file pcap thô của bộ dữ liệu chuẩn CIC-IDS2017 với 83 bài kiểm thử tự động, nhóm nghiên cứu phát hiện kết quả công bố của bài báo (**TPR 99,04% ở FPR 6,56%**) **không thể tái lập trong môi trường IDS thời gian thực, không rò rỉ dữ liệu** (kết quả tái hiện sạch Protocol T đạt TPR 11,4% ở FPR 2,5%, AUROC 0,668).

Qua điều tra chuyên sâu và phân tích pháp chứng mã nguồn mở chính thức của tác giả (tại kho lưu trữ `jalalgh7/graph-representation-learning-for-NIDS` và `jalalgh7/robust-and-real-time-NIDS`), nhóm đã xác định được **4 nguyên nhân kỹ thuật cốt lõi** dẫn đến sự sai lệch:
1. **Lỗi lệch nhãn gói tin (Label Row-Shift):** Lỗi logic thiếu nhánh `else` trong vòng lặp tiền xử lý khiến cột nhãn tấn công bị trượt hàng, gán nhầm vào lưu lượng bình thường đầu ngày.
2. **Lỗi ngắt kết nối Transformer Encoder:** Mã nguồn Autoencoder trong repo tác giả tính toán `edge_features` nhưng lại truyền thẳng `features` thô vào `decoder`, khiến Graph Transformer Encoder bị cô lập hoàn toàn và không tham gia vào quá trình huấn luyện hay trích xuất đặc trưng.
3. **Sai lệch phân chia dữ liệu:** Tác giả không huấn luyện trên ngày thứ Hai sạch (Monday benign) xuyên suốt tuần như công bố, mà huấn luyện và kiểm thử trên cùng ngày thứ Sáu (Friday 70/30 split).
4. **Quy tắc Ensemble và ghép chỉ số:** Tác giả sử dụng luật hợp logic (OR, `votes >= 1`) thay vì đa số (Majority voting), khiến FPR thực tế trên lưu lượng bình thường tăng vọt lên **13,12%**, nhưng bài báo lại ghép chỉ số TPR của Ensemble (99,04%) với FPR của riêng thuật toán OCSVM (6,56%).

Nhằm giải quyết triệt để các hạn chế của mô hình gốc, nhóm đề xuất **Proposal P1: Calibrated Conformal Fusion & Sequential Early-Exit**. P1 chuyển đổi điểm số bất thường sang conformal p-value trên tập hiệu chuẩn lành tính để kiểm soát FPR thực nghiệm, đồng thời cho phép hệ thống đưa ra quyết định cảnh báo sớm ngay từ $p=2..7$ gói tin đầu tiên mà không cần chờ đủ $p=8$. Với calibration 40% của `train2` (800 flow), Bonferroni đạt **TPR 16,92% @ FPR 3,43%** ở $\alpha=0,05$ và **23,47% @ 6,18%** ở $\alpha=0,10$; Fisher cho TPR 47,7% nhưng FPR 17,7%, nên chỉ là kết quả exploratory. Tại FPR=1%, P1 (0–6,07%) chưa vượt M1 (9,64%), nên đóng góp của P1 là operating point có kiểm soát FPR và phân tích trade-off, không phải cải thiện mọi metric.

---

## CHƯƠNG 1: GIỚI THIỆU VÀ ĐỘNG CƠ NGHIÊN CỨU

### 1.1 Bài toán Phát hiện Xâm nhập Mạng (NIDS)
Hệ thống phát hiện xâm nhập mạng đóng vai trò huyết mạch trong phòng thủ an ninh không gian mạng. Phần lớn các NIDS truyền thống dựa trên hai phương pháp chính:
- **NIDS dựa trên luật (Signature-based):** Sử dụng các mẫu nhận dạng cố định (như tập luật Snort/Suricata). Phương pháp này đạt độ chính xác cao đối với các mối đe dọa đã biết nhưng hoàn toàn bất lực trước tấn công zero-day và các biến thể mã độc đa hình.
- **NIDS dựa trên thống kê luồng (Statistical Flow-based):** Sử dụng các công cụ như CICFlowMeter để trích xuất 80+ đặc trưng thống kê tổng hợp (thời gian liên gói tin, độ lệch chuẩn độ dài gói, cờ TCP,...). Điểm yếu chí tử của phương pháp này là **độ trễ cao** (phải chờ luồng mạng kết thúc hoặc hết thời gian timeout 120s mới trích xuất được đặc trưng), khiến việc ngăn chặn tấn công theo thời gian thực (in-line prevention) trở nên bất khả thi.

### 1.2 Động cơ nghiên cứu GTAE-IDS
Bài báo của Ghadermazi et al. (IEEE TIFS 2025) đề xuất khung làm việc **GTAE-IDS** nhằm giải quyết hai bài toán lớn:
1. **Phát hiện sớm (Early Detection):** Chỉ sử dụng $p$ gói tin đầu tiên ($p \in \{2, \dots, 8\}$) của mỗi luồng mạng, trích xuất 25 byte đầu của IP/TCP header để ra quyết định ngay khi luồng vừa khởi tạo.
2. **Học không giám sát (Unsupervised Graph Transformer Autoencoder):** Tận dụng cấu trúc liên kết đồ thị mạng (Graph structure) kết hợp với cơ chế chú ý (Self-Attention) để học phân phối của lưu lượng bình thường (Benign), sau đó sử dụng tập hợp 4 thuật toán phát hiện bất thường (OCSVM, IForest, HBOS, INNE) để gắn cờ các hành vi bất thường mà không cần nhãn tấn công khi huấn luyện.

---

## CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VÀ PHÂN TÍCH PHƯƠNG PHÁP

### 2.1 Biểu diễn Gói tin và Đồ thị Mạng trong GTAE-IDS
- **Đặc trưng gói tin (Fig. 3):** Mỗi gói tin TCP/IPv4 được giữ lại 9 byte từ IP Header (bỏ phiên bản, IHL, ToS, TTL, Checksum, Địa chỉ IP nguồn/đích) và 16 byte từ TCP Header (bỏ Source Port, Destination Port, Checksum, Urgent Pointer). Chuỗi 25 byte này được chuẩn hóa chia cho 255 về miền $[0, 1]$.
- **Hướng truyền thông (Directional Padding, Fig. 4):** Mỗi bước truyền thông được biểu diễn bằng vector 50 chiều. Nếu gói tin theo chiều thuận (Forward - fwd), 25 byte đặc trưng nằm ở nửa đầu, nửa sau chèn 25 số 0. Ngược lại, nếu theo chiều nghịch (Backward - bwd), nửa đầu là 25 số 0, nửa sau chứa 25 byte đặc trưng. Với $p$ gói tin, mỗi cạnh đồ thị mang vector đặc trưng có chiều dài $50 \times p$ (ví dụ: $p=8 \implies 400$ chiều).
- **Cấu trúc đồ thị snapshot:** Các thực thể mạng được biểu diễn dưới dạng đỉnh $u = (\text{IP}, \text{Port})$, và mỗi luồng giao tiếp là một cạnh nối $e = (u, v)$.

### 2.2 Kiến trúc Line-Graph Transformer Autoencoder
Thay vì áp dụng Transformer truyền thống lên đỉnh, GTAE mô hình hóa tương tác giữa các luồng bằng cách chuyển đổi sang **Line Graph** $\mathcal{L}(G)$, trong đó các cạnh của đồ thị gốc trở thành các đỉnh của đồ thị đường bao.
- **Cơ chế Attention trên Line Graph:** Ma trận tự chú ý đa đầu (Multi-Head Attention) được tính toán giữa các cạnh kề nhau chia sẻ chung nút giao tiếp:
  $$\text{Attn}(e_i, e_j) = \text{Softmax}\left(\frac{(e_i W_Q)(e_j W_K)^T}{\sqrt{d}} + \mathcal{N}(e_i, e_j)\right)(e_j W_V)$$
- **Laplacian Positional Encoding (LapPE):** Nhúng vector riêng của ma trận Laplacian chuẩn hóa ($k=8$ chiều) để bổ sung thông tin vị trí không gian liên kết đồ thị.
- **Decoder:** Mạng nơ-ron truyền thẳng (DNN) tái tạo lại vector đặc trưng $50p$ chiều với hàm mất mát MSE.

### 2.3 Mô hình Phát hiện Bất thường & Cơ chế Bầu chọn
Sau khi huấn luyện Autoencoder trên đồ thị lưu lượng bình thường (Train 1), không gian nhúng tiềm ẩn (Embedding) của tập Train 2 được dùng để huấn luyện 4 thuật toán phát hiện bất thường:
1. **One-Class SVM (OCSVM):** Tìm siêu phẳng cực đại hóa khoảng cách bao bọc dữ liệu lành tính.
2. **Isolation Forest (IForest):** Cô lập các điểm dữ liệu bất thường bằng cây quyết định nhị phân ngẫu nhiên.
3. **Histogram-based Outlier Score (HBOS):** Ước lượng mật độ độc lập qua biểu đồ tần số.
4. **Isolation-based Neural Network Ensemble (INNE):** Dùng siêu cầu ngẫu nhiên cô lập không gian thưa thớt.

Bài báo công bố sử dụng luật bầu chọn đa số (Majority Voting) giữa 4 bộ dò để đưa ra phán quyết cuối cùng.

---

## CHƯƠNG 3: QUÁ TRÌNH TÁI HIỆN VÀ KIỂM THỬ ĐỘC LẬP

### 3.1 Pipeline Tái hiện Chuẩn mực
Nhóm nghiên cứu đã xây dựng lại toàn bộ pipeline mã nguồn Python độc lập:
- `src/parse_pcap.py`: Bộ đọc luồng pcap/pcapng streaming tối ưu, quản lý 5-tuple, SYN/FIN handshake, tách luồng idle > 120s.
- `src/packet_encoder.py`: Trích xuất 25 byte header chính xác theo Fig. 3 và kiểm chứng bằng test vector độc lập.
- `src/graph_builder.py`: Khởi tạo đồ thị PyG/NetworkX, mã hóa cạnh, hỗ trợ cả hai giao thức chia tách:
  - **Protocol T (Temporal):** Train trên thứ Hai sạch, Test trên thứ Ba đến thứ Sáu (mô phỏng đúng môi trường thực tế).
  - **Protocol R (Random):** Chia ngẫu nhiên theo luồng trên toàn bộ các ngày (để đối chứng với paper).
  - **T_fixed:** Cố định quần thể 30.907 luồng có $\ge 8$ gói tin xuyên suốt $p=2 \dots 8$ để đo chính xác đường cong phụ thuộc $p$.
- `src/model_gtae.py` & `src/train_gtae.py`: Cài đặt LineGraph Transformer đúng bảng kiến trúc Table III, huấn luyện 21 mô hình (7 giá trị $p \times 3$ seed) trên Kaggle GPU T4 đạt mức giảm MSE $\ge 50\%$.

### 3.2 Bộ Kiểm thử Tự động & Đảm bảo Không Rò rỉ (Zero-Leakage)
- Hệ thống đạt **83/83 test pytest pass** (gồm kiểm tra không chứa IP/Port trong đặc trưng, kiểm tra tính độc lập tuyệt đối giữa tập Train và Test).
- Script kiểm định tự động `scripts/audit_artifacts.py` thực hiện **428/428 phép kiểm tra chéo** trên toàn bộ 89 MB artifact đã trích xuất.

---

## CHƯƠNG 4: PHÁT HIỆN PHẢN BIỆN KHOA HỌC: MỔ XẺ MÃ NGUỒN GỐC CỦA TÁC GIẢ

Khi đánh giá mô hình tái hiện sạch dưới Protocol T, nhóm ghi nhận kết quả rất thấp: TPR chỉ đạt **11,36%** ở FPR **2,47%** (AUROC 0,668) tại $p=8$, hoàn toàn mâu thuẫn với con số **99,04%** của bài báo.
Nhóm đã tiến hành điều tra kỹ thuật sâu trên các kho lưu trữ mã nguồn của tác giả chính (Jalal Ghadermazi) và phát hiện **4 sai sót kỹ thuật mang tính hệ thống**:

### 4.1 Lỗi lệch nhãn gói tin do cấu trúc `if` thiếu `else` (`data_extraction/*.ipynb`)
Trong mã nguồn trích xuất dữ liệu của tác giả:
```python
if float(epoch_time) >= ftp_start and float(epoch_time) <= ftp_end:
    if source_ip == '172.16.0.1' and dst_ip == '192.168.10.50':
        dict_direction[packets] = 'fwd'
        dict_d_labels[packets] = 6
        dict_b_labels[packets] = 1
    elif source_ip == '192.168.10.50' and dst_ip == '172.16.0.1':
        dict_direction[packets] = 'bwd'
        dict_d_labels[packets] = 6
        dict_b_labels[packets] = 1
    # THIẾU NHÁNH ELSE!
else:
    dict_direction[packets] = 'unknown'
    dict_d_labels[packets] = 0
    dict_b_labels[packets] = 0
```
Khi gói tin nằm trong khung giờ tấn công nhưng thuộc về các địa chỉ IP bình thường nền, từ điển `dict_d_labels` **không được gán giá trị**. Khi tạo DataFrame:
```python
payload_byte_data['Epoch Time'] = pd.DataFrame(dict_epochtime.values())
payload_byte_data['Class Label'] = pd.DataFrame(dict_d_labels.values())
payload_byte_data = payload_byte_data.dropna()
```
Số phần tử của nhãn ít hơn số gói tin thực tế, khiến toàn bộ cột nhãn bị **dịch chuyển hàng (Row-Shift)**: gói tin bình thường duyệt web đầu ngày (như Microsoft Bing port 80) bị gán nhãn thành tấn công `FTP-Patator` (Class 6).

### 4.2 Lỗi ngắt kết nối Graph Transformer Encoder (`GTAE_8pkt.ipynb`)
Tại Cell 24 của file huấn luyện chính:
```python
class GraphAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers):
        super().__init__()
        self.transformer_encoder = nn.TransformerEncoder(...)
        self.decoder = nn.Linear(input_dim, input_dim)

    def forward(self, g, features):
        edge_features = self.transformer_encoder(features)
        decoded_features = self.decoder(features)  # TRUYỀN FEATURES THÔ VÀO DECODER!
        return decoded_features
```
Biến `edge_features` (kết quả của Transformer Encoder) bị bỏ qua hoàn toàn. Mô hình thực chất chỉ là một mạng tuyến tính `Linear(400, 400)` tái tạo trực tiếp vector đặc trưng. Cơ chế Graph Transformer được giới thiệu rầm rộ trong paper thực tế **hoàn toàn không hoạt động trong code của tác giả**.

### 4.3 Phân chia dữ liệu sai lệch (Same-Day Split)
Paper công bố mô hình được huấn luyện trên ngày thứ Hai (Monday) và kiểm thử trên các ngày còn lại. Tuy nhiên trong mã nguồn:
- Tác giả huấn luyện trên 5.000 luồng của **Friday Benign 70%**.
- Kiểm thử Benign trên 5.000 luồng của **Friday Benign 30%**.
Do cùng một môi trường mạng và cùng phiên lưu lượng, mô hình chỉ ghi nhớ phân phối tĩnh của ngày thứ Sáu chứ không thể tổng quát hóa cho các ngày khác.

### 4.4 Quy tắc Bầu chọn OR và ghép nối chỉ số (Cherry-Picking)
- Trong code tác giả:
  ```python
  anomalies_ensemble = (votes >= 1).astype(int)  # LUẬT HỢP OR!
  ```
  Chỉ cần 1 trong 4 bộ dò báo bất thường thì tính là tấn công. Điều này đẩy TPR lên cao nhưng đồng thời đẩy **FPR trên Benign lên 13,12%** (được ghi nhận trong file `Final_Results_8pkt_Anomaly_Detection_2017.csv` của chính tác giả).
- Bài báo đã lấy con số **TPR của Ensemble (99,04%)** ghép chung với con số **FPR của riêng OCSVM (6,56%)** để công bố, tạo ra ảo tưởng về một mô hình vừa có độ nhạy vượt trội vừa có tỷ lệ báo động giả thấp.

---

## CHƯƠNG 5: SO SÁNH KẾT QUẢ THỰC NGHIỆM ĐỐI CHỨNG

### 5.1 Bảng Tổng hợp Kết quả Đa phương diện (p = 8)

| Phương pháp | Loại mô hình | Phân chia dữ liệu | Luật quyết định | TPR | FPR | AUROC |
|---|---|---|---|---:|---:|---:|
| **Paper Table VI** | Graph Transformer AE | Random / Same-day | Majority vote (Công bố) | **99,04%** | **6,56%** | — |
| **Official Repo Code** | Disconnected Linear AE | Friday 70/30 | Union (votes $\ge 1$) | **98,74%** | **13,12%** | — |
| **B0: Raw Vector** | PyOD Detectors (Không đồ thị) | Temporal T | Ensemble tie ($\ge 2/4$) | **0,50%** | **1,22%** | **0,698** |
| **B1: MLP-AE** | Dense AE (Không đồ thị) | Temporal T | Ensemble tie ($\ge 2/4$) | **6,29%** | **2,29%** | **0,595** |
| **M1: GTAE-IDS (Ours Sạch)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,36%** | **2,47%** | **0,668** |
| **M1 (Chạy theo luật Code)** | Graph Transformer AE | Friday same-day | Union (votes $\ge 1$) | *chưa lưu artifact* | — | — |
| **P1: Bonferroni α=0,05** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **16,92%** | **3,43%** | **0,656** |
| **Upper Bound (Supervised RF)** | Random Forest | Cross-day (Tue/Wed $\to$ Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** |
| **Upper Bound (Same-session RF)** | Random Forest | Same-session (Cùng ngày) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** |

*Lưu ý: B0 `ensemble_tie` rất thấp; detector INNE trên raw features đạt 10,21% @ 2,45%, gần M1. Cần so cùng detector/FPR trước khi kết luận graph transformer tốt hơn. Dòng “M1 (Chạy theo luật Code)” chưa có artifact lưu nên không dùng làm kết luận. P1 Bonferroni α=0,05 có TPR@FPR=1% = 0%, thấp hơn M1 (9,64%).*

### 5.2. Ablation A3 — Reconstruction-error detector

A3 thay 4 detector bằng ngưỡng 99th percentile của reconstruction MSE trên `train2`; không train lại.

| p | M1 TPR/FPR | A3 TPR/FPR | A3 AUROC | ΔTPR (A3−M1) |
|---:|---:|---:|---:|---:|
| 2 | 8,58% / 5,90% | 4,58% / 3,71% | 0,436 | −4,00 pp |
| 4 | 11,70% / 3,62% | 7,40% / 1,73% | 0,543 | −4,30 pp |
| 8 | 11,36% / 2,47% | **23,65% / 4,17%** | 0,676 | **+12,29 pp** |

A3 chỉ có lợi thế rõ ở p=8, nhưng tại FPR 4,17% (cao hơn M1 2,47%); p=2/4 lại kém M1. Vì vậy không thể kết luận A3 “tốt hơn” nếu không so cùng operating point. Chi tiết sinh tự động: [`reports/ablation.md`](../reports/ablation.md).

**A2 — bỏ LapPE (p=8):** TPR **6,21% ± 7,97%** @ FPR **2,24%**, AUROC **0,690**, TPR@1% **9,31%**. Seed variance rất lớn (0,2–15,3% TPR), nên LapPE không phải yếu tố quyết định; A2 thấp hơn M1 về TPR trung bình nhưng AUROC tương đương.

---

## CHƯƠNG 6: ĐỀ XUẤT CẢI TIẾN P1: CALIBRATED CONFORMAL FUSION & EARLY EXIT

### 6.1 Cơ chế Conformal P-Value và Hợp nhất Điểm số
Để giải quyết bài toán bùng nổ báo động giả (FPR) khi kết hợp nhiều bộ dò bất thường, P1 sử dụng lý thuyết suy luận bảo đảm phân phối (Conformal Prediction):
1. Chuẩn hóa điểm bất thường liên tục $s_m(x)$ của mỗi bộ dò thành **conformal p-value** dựa trên tập hiệu chuẩn lành tính $\mathcal{C}$:
   $$\pi_m(x) = \frac{1 + \sum_{c \in \mathcal{C}} \mathbb{I}(s_m(c) \ge s_m(x))}{1 + |\mathcal{C}|}$$
2. Hợp nhất các p-value bằng **Bonferroni** hoặc **Fisher**:
   - Bonferroni: $\pi_{\text{fused}}(x) = \min(1, M \cdot \min_m \pi_m(x))$. Đây là test hợp lệ theo conformal nếu calibration và benign test exchangeable; FPR bị chặn trên bởi $\alpha$.
   - Fisher: $T = -2 \sum_{m=1}^M \ln(\pi_m(x)) \sim \chi^2(2M)$; $\pi_{\text{fused}}(x) = 1 - F_{\chi^2(2M)}(T)$. Fisher chỉ đúng khi các p-value độc lập; 4 detector trong GTAE tương quan mạnh nên Fisher không còn bảo đảm FPR và chỉ được báo cáo như exploratory.
   Hệ thống gắn cờ cảnh báo bất thường khi $\pi_{\text{fused}}(x) \le \alpha$.

### 6.2 Cơ chế Ra Quyết Định Dừng Sớm (Sequential Early-Exit)
Thay vì bắt buộc phải thu thập đủ $p=8$ gói tin mới đưa ra quyết định, P1 kiểm tra liên tục tại mỗi bước $p \in \{2, 3, \dots, 8\}$:
- Ngân sách báo động giả được phân bổ theo nguyên lý Bonferroni: $\alpha_p = \alpha / 7$.
- Calibration dùng 40% của `train2` (800/2.000 flow), phần còn lại fit detector. Với 400 flow (20%), sàn p-value $4/401 > \alpha/7$ khiến Bonferroni tại $\alpha=0,05$ không thể alert; 800 flow hạ sàn xuống $4/801$ và mở được operating point này.
- Tại bước $p$, nếu $\pi_{\text{fused}, p}(x) \le \alpha_p \implies$ **Báo động ngay lập tức (Early Exit)**, dừng thu thập gói tin cho luồng này và gán `p_decision = p`.
- Nếu đến $p=8$ mà không bước nào kích hoạt cảnh báo $\implies$ Kết luận luồng bình thường (Benign), gán `p_decision = 8`.

### 6.3 Kết quả Thực nghiệm của P1 trên Quần thể Cố định (T_fixed)

Chi tiết sinh tự động từ CSV: [`reports/P1.md`](../reports/P1.md).

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) | AUROC | TPR@FPR=1% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **0,01** | Fisher | 39,87% | 11,81% | 6,42 pkts | 7,44 pkts | 39,66% | 0,646 | 6,07% |
| **0,05** | Fisher | **47,67%** | **17,73%** | **5,90 pkts** | 7,14 pkts | **47,47%** | 0,646 | 6,07% |
| **0,10** | Fisher | 51,43% | 22,26% | 5,72 pkts | 6,92 pkts | 51,15% | 0,646 | 6,07% |
| **0,01** | Bonferroni | 0,00% | 0,00% | 8,00 pkts | 8,00 pkts | 0,00% | 0,656 | 0,00% |
| **0,05** | Bonferroni | **16,92%** | **3,43%** | 7,57 pkts | 7,89 pkts | 15,66% | 0,656 | 0,00% |
| **0,10** | Bonferroni | **23,47%** | **6,18%** | 7,33 pkts | 7,79 pkts | 22,24% | 0,656 | 0,00% |

*Calibration: 40% của `train2` (800 flow); detector fit trên 1.200 flow còn lại. Số liệu mean 3 seed trên T_fixed. Score cho AUROC/TPR@FPR=1% là $1-\min_p$ qua các p.*

**Đánh giá:**
1. **Bonferroni kiểm soát FPR:** Tại $\alpha = 0,05$, FPR thực đo là **3,43%** ($\le 5\%$); tại $\alpha=0,10$ là **6,18%** ($\le 10\%$). Đây là cấu hình dùng được cho claim kiểm soát FPR theo conformal, với giả định calibration và benign test exchangeable.
2. **Fisher không kiểm soát FPR:** Fisher cho TPR 39,9–51,4% nhưng FPR 11,8–22,3%, vượt xa $\alpha$. Nguyên nhân: Fisher giả định 4 p-value độc lập, trong khi 4 detector tương quan mạnh; kết quả này chỉ nên đọc như exploratory.
3. **Calibration floor:** Với 400 calibration flow (20%), Bonferroni tại $\alpha=0,05$ không thể alert vì $4/401=0,009975 > 0,05/7$. Tăng calibration lên 800 flow (40%) đưa sàn xuống $4/801=0,004994$, mở được operating point $\alpha=0,05$; $\alpha=0,01$ vẫn không thể alert.
4. **Early-exit:** Bonferroni $\alpha=0,05$ phát hiện sớm 15,66% attack, APD 7,57 gói (giảm 5,4% so với 8); $\alpha=0,10$ phát hiện sớm 22,24%, APD 7,33 gói. Fisher giảm APD mạnh hơn (5,90 gói ở $\alpha=0,05$) nhưng không dùng được vì FPR cao.
5. **Giới hạn quan trọng:** Ở operating point FPR=1%, Bonferroni không alert (TPR 0%) và Fisher chỉ đạt 6,07%, đều thấp hơn M1 (9,64%). Vì vậy P1 chưa vượt M1 ở vùng FPR thấp; đóng góp chính là một operating point có kiểm soát FPR và phân tích trade-off/calibration, không phải cải thiện tuyệt đối mọi metric.

---

## CHƯƠNG 7: KẾT LUẬN VÀ ĐÓNG GÓP HỌC THUẬT

1. **Tính trung thực khoa học:** Đồ án không che giấu kết quả âm khi tái hiện, mà đi sâu tìm hiểu bản chất và cung cấp bằng chứng mổ xẻ mã nguồn thuyết phục, giải trình tường tận lý do bài báo IEEE TIFS 2025 công bố con số 99% không tưởng.
2. **Kỹ thuật công nghệ vững chắc:** Xây dựng hệ thống pipeline hoàn chỉnh, xử lý 51 GB pcap với 83 bài kiểm thử tự động, kiểm toán 428 tiêu chí không rò rỉ dữ liệu.
3. **Đóng góp giải pháp thực tiễn (P1):** Đề xuất và đánh giá trung thực Early-Exit kết hợp Conformal Prediction. Bonferroni với 800 calibration flow kiểm soát FPR (3,43% @ α=0,05; 6,18% @ α=0,10) và tăng TPR so với M1 ở vùng FPR 3–6%, nhưng chưa vượt M1 tại FPR=1%; Fisher có TPR cao hơn nhưng FPR 17,7–22,3% nên chỉ là exploratory. Đóng góp là phân tích trade-off FPR/TPR/APD và giới hạn calibration, không phải một cải tiến thắng mọi metric.
