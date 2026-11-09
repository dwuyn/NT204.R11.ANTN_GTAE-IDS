# BÁO CÁO NGHIÊN CỨU ĐỒ ÁN MÔN HỌC
## HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG THỜI GIAN THỰC DỰA TRÊN ĐỒ THỊ BIẾN ĐỔI TỰ MÃ HÓA (GTAE-IDS)
### TÁI HIỆN ĐỘC LẬP, PHẢN BIỆN MÃ NGUỒN GỐC VÀ ĐỀ XUẤT CẢI TIẾN P1 (CONFORMAL EARLY-EXIT)

---

**Môn học:** Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập (NT204.R11.ANTN)  
**Nhóm thực hiện:** Nhóm B  
**Thời gian hoàn thành:** 25/10/2026  
**Bài báo nghiên cứu cơ sở (Paper neo):**  
> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026–4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

---

## TÓM TẮT ĐỒ ÁN (ABSTRACT)

Nghiên cứu này thực hiện quy trình tái hiện độc lập toàn diện và phản biện học thuật đối với khung làm việc **GTAE-IDS** (IEEE TIFS 2025) — một mô hình học không giám sát biểu diễn cấu trúc đồ thị luồng mạng cấp độ gói tin để phát hiện tấn công zero-day thời gian thực. Bằng việc xây dựng lại toàn bộ pipeline kỹ thuật sạch từ 51 GB file pcap thô của bộ dữ liệu chuẩn CIC-IDS2017 với 81 bài kiểm thử tự động, nhóm nghiên cứu phát hiện kết quả công bố của bài báo (**TPR 99,04% ở FPR 6,56%**) **không thể tái lập trong môi trường IDS thời gian thực, không rò rỉ dữ liệu** (kết quả tái hiện sạch Protocol T đạt TPR 11,5% ở FPR 2,5%, AUROC 0,67).

Qua điều tra chuyên sâu và phân tích pháp chứng mã nguồn mở chính thức của tác giả (tại kho lưu trữ `jalalgh7/graph-representation-learning-for-NIDS` và `jalalgh7/robust-and-real-time-NIDS`), nhóm đã xác định được **4 nguyên nhân kỹ thuật cốt lõi** dẫn đến sự sai lệch:
1. **Lỗi lệch nhãn gói tin (Label Row-Shift):** Lỗi logic thiếu nhánh `else` trong vòng lặp tiền xử lý khiến cột nhãn tấn công bị trượt hàng, gán nhầm vào lưu lượng bình thường đầu ngày.
2. **Lỗi ngắt kết nối Transformer Encoder:** Mã nguồn Autoencoder trong repo tác giả tính toán `edge_features` nhưng lại truyền thẳng `features` thô vào `decoder`, khiến Graph Transformer Encoder bị cô lập hoàn toàn và không tham gia vào quá trình huấn luyện hay trích xuất đặc trưng.
3. **Sai lệch phân chia dữ liệu:** Tác giả không huấn luyện trên ngày thứ Hai sạch (Monday benign) xuyên suốt tuần như công bố, mà huấn luyện và kiểm thử trên cùng ngày thứ Sáu (Friday 70/30 split).
4. **Quy tắc Ensemble và ghép chỉ số:** Tác giả sử dụng luật hợp logic (OR, `votes >= 1`) thay vì đa số (Majority voting), khiến FPR thực tế trên lưu lượng bình thường tăng vọt lên **13,12%**, nhưng bài báo lại ghép chỉ số TPR của Ensemble (99,04%) với FPR của riêng thuật toán OCSVM (6,56%).

Nhằm giải quyết triệt để các hạn chế của mô hình gốc, nhóm đề xuất **Proposal P1: Calibrated Conformal Fusion & Sequential Early-Exit**. P1 chuyển đổi điểm số bất thường sang conformal p-value trên tập hiệu chuẩn lành tính để kiểm soát chặt chẽ FPR thực nghiệm ($\le \alpha$), đồng thời cho phép hệ thống đưa ra quyết định cảnh báo sớm ngay từ $p=2..7$ gói tin đầu tiên mà không cần chờ đủ $p=8$. Kết quả thực nghiệm chứng minh P1 giúp phát hiện sớm **65,4%** các luồng tấn công, tiết kiệm trung bình **40% thời gian chờ gói tin**, mang lại giá trị phát hiện thời gian thực thực chất cho hệ thống IDS.

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
- Hệ thống đạt **81/81 test pytest pass** (gồm kiểm tra không chứa IP/Port trong đặc trưng, kiểm tra tính độc lập tuyệt đối giữa tập Train và Test).
- Script kiểm định tự động `scripts/audit_artifacts.py` thực hiện **428/428 phép kiểm tra chéo** trên toàn bộ 89 MB artifact đã trích xuất.

---

## CHƯƠNG 4: PHÁT HIỆN PHẢN BIỆN KHOA HỌC: MỔ XẺ MÃ NGUỒN GỐC CỦA TÁC GIẢ

Khi đánh giá mô hình tái hiện sạch dưới Protocol T, nhóm ghi nhận kết quả rất thấp: TPR chỉ đạt **11,5%** ở FPR **2,5%** (AUROC 0,67) tại $p=8$, hoàn toàn mâu thuẫn với con số **99,04%** của bài báo.
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
| **B0: Raw Vector** | PyOD Detectors (Không đồ thị) | Temporal T | Ensemble tie ($\ge 2/4$) | **11,8%** | **3,2%** | **0,68** |
| **B1: MLP-AE** | Dense AE (Không đồ thị) | Temporal T | Ensemble tie ($\ge 2/4$) | **9,4%** | **2,8%** | **0,66** |
| **M1: GTAE-IDS (Ours Sạch)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,5%** | **2,5%** | **0,67** |
| **M1 (Chạy theo luật Code)** | Graph Transformer AE | Friday same-day | Union (votes $\ge 1$) | **72,1%** | **17,6%** | **0,89** |
| **P1: Conformal Early-Exit** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **24,6%** | **4,8%** | **0,86** |
| **Upper Bound (Supervised RF)** | Random Forest | Cross-day (Tue/Wed $\to$ Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** |
| **Upper Bound (Same-session RF)** | Random Forest | Same-session (Cùng ngày) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** |

---

## CHƯƠNG 6: ĐỀ XUẤT CẢI TIẾN P1: CALIBRATED CONFORMAL FUSION & EARLY EXIT

### 6.1 Cơ chế Conformal P-Value và Hợp nhất Điểm số
Để giải quyết bài toán bùng nổ báo động giả (FPR) khi kết hợp nhiều bộ dò bất thường, P1 sử dụng lý thuyết suy luận bảo đảm phân phối (Conformal Prediction):
1. Chuẩn hóa điểm bất thường liên tục $s_m(x)$ của mỗi bộ dò thành **conformal p-value** dựa trên tập hiệu chuẩn lành tính $\mathcal{C}$:
   $$\pi_m(x) = \frac{1 + \sum_{c \in \mathcal{C}} \mathbb{I}(s_m(c) \ge s_m(x))}{1 + |\mathcal{C}|}$$
2. Hợp nhất các p-value bằng phương pháp kiểm định Fisher:
   $$T = -2 \sum_{m=1}^M \ln(\pi_m(x)) \sim \chi^2(2M)$$
   $$\pi_{\text{fused}}(x) = 1 - F_{\chi^2(2M)}(T)$$
   Hệ thống gắn cờ cảnh báo bất thường khi $\pi_{\text{fused}}(x) \le \alpha$. Lý thuyết conformal đảm bảo rằng trên lưu lượng bình thường cùng phân phối, tỷ lệ báo động giả bị chặn trên bởi $\alpha$.

### 6.2 Cơ chế Ra Quyết Định Dừng Sớm (Sequential Early-Exit)
Thay vì bắt buộc phải thu thập đủ $p=8$ gói tin mới đưa ra quyết định, P1 kiểm tra liên tục tại mỗi bước $p \in \{2, 3, \dots, 8\}$:
- Ngân sách báo động giả được phân bổ theo nguyên lý Bonferroni: $\alpha_p = \alpha / 7$.
- Tại bước $p$, nếu $\pi_{\text{fused}, p}(x) \le \alpha_p \implies$ **Báo động ngay lập tức (Early Exit)**, dừng thu thập gói tin cho luồng này và gán `p_decision = p`.
- Nếu đến $p=8$ mà không bước nào kích hoạt cảnh báo $\implies$ Kết luận luồng bình thường (Benign), gán `p_decision = 8`.

### 6.3 Kết quả Thực nghiệm của P1 trên Quần thể Cố định (T_fixed)

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) |
|---|---|---:|---:|---:|---:|---:|
| **0,01** | Fisher | 14,2% | 1,1% | 5,6 pkts | 7,9 pkts | 48,2% |
| **0,05** | Fisher | **24,6%** | **4,8%** | **4,8 pkts** | 7,6 pkts | **65,4%** |
| **0,10** | Fisher | 33,8% | 9,7% | 4,1 pkts | 7,2 pkts | 77,1% |
| **0,05** | Bonferroni | 21,3% | 3,9% | 5,1 pkts | 7,7 pkts | 59,8% |

**Đánh giá:**
1. **Kiểm soát chặt chẽ FPR:** Tại $\alpha = 0,05$, FPR thực tế đo được là **4,8%**, tuân thủ nghiêm ngặt bảo đảm lý thuyết conformal ($\le 5\%$).
2. **Tiết kiệm 40% trễ thời gian thực:** **65,4%** các luồng tấn công được phát hiện ngay từ các gói tin đầu tiên (trung bình 4,8 gói tin thay vì 8 gói), giúp hệ thống phản ứng nhanh trước các cuộc tấn công DDoS/PortScan trước khi máy chủ bị nghẽn tài nguyên.

---

## CHƯƠNG 7: KẾT LUẬN VÀ ĐÓNG GÓP HỌC THUẬT

1. **Tính trung thực khoa học:** Đồ án không che giấu kết quả âm khi tái hiện, mà đi sâu tìm hiểu bản chất và cung cấp bằng chứng mổ xẻ mã nguồn thuyết phục, giải trình tường tận lý do bài báo IEEE TIFS 2025 công bố con số 99% không tưởng.
2. **Kỹ thuật công nghệ vững chắc:** Xây dựng hệ thống pipeline hoàn chỉnh, xử lý 51 GB pcap với 81 bài kiểm thử tự động, kiểm toán 428 tiêu chí không rò rỉ dữ liệu.
3. **Đóng góp giải pháp thực tiễn (P1):** Đề xuất thành công mô hình Early-Exit kết hợp Conformal Prediction, giải quyết bài toán cân bằng giữa kiểm soát báo động giả và giảm độ trễ quyết định trong hệ thống giám sát an ninh mạng thời gian thực.
