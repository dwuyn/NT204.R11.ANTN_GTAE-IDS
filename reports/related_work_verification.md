# Đối chiếu số liệu related work với PDF gốc

**Ngày:** 2026-11-22. **Mục đích:** kiểm tra các con số trong `reports/related_work.md` và
Table XI–XIII của bài neo ([1]) có đúng là số do bài gốc báo hay không.

**PDF gốc đã tải** (trong `docs/related/`):

| file | bài | nguồn |
|---|---|---|
| `egraphsage.pdf` | Lo, Layeghy, Sarhan, Gallagher, Portmann, *E-GraphSAGE*, IEEE/IFIP NOMS 2022 | arXiv:2103.16329v8 (9 trang) |
| `anomale.pdf` | Caville, Lo, Layeghy, Portmann, *Anomal-E*, Knowledge-Based Systems 258:110030, 2022 | arXiv:2207.06819v5 (12 trang) |
| `pujol_perich.pdf` | Pujol-Perich, Suárez-Varela, et al., *Unveiling the potential of GNNs for robust Intrusion Detection* | arXiv:2107.14756v1 (7 trang) |

Không tải được (paywall hoặc chặn): PBCNN (Elsevier), SPIN-IDS (IEEE TBD 2025), GraphDDoS
(IEEE), GraphIDS (không xác định được bài gốc), Kitsune (NDSS trả HTML thay PDF).

---

## 1. Kết quả đối chiếu

| Số trong bài neo [1] | Bài gốc nói gì | Khớp? |
|---|---|---|
| **Table XI, dòng E-GraphSAGE**: TPR từng lớp trên **CIC-IDS2017** (0,954–0,992) | E-GraphSAGE đánh giá trên **NF-UNSW-NB15, NF-ToN-IoT, NF-BoT-IoT** (NetFlow), metric **Accuracy/Precision/F1/Recall/FAR** (Bảng 2–4). **Không** có CIC-IDS2017, **không** có TPR từng lớp. | **Không có trong bài gốc.** Số của [1] là kết quả tính lại (hoặc lấy từ nguồn khác) nhưng [1] không nêu; **không nên trích như số của E-GraphSAGE**. |
| **Table XI, dòng Pujol-Perich**: TPR từng lớp 0,734–0,993 (gồm cả Heartbleed 0,978, Infiltration 0,983) | Bài gốc Bảng 1 (tr. 4) báo **accuracy từng lớp** trên CIC-IDS2017 cho "Our proposal": Benign 0,99; SSH 0,98; FTP 0,99; GoldenEye 0,99; Hulk 0,99; slowloris 0,98; Slowhttptest 0,97; DDoS 0,99; **Web-Brute Force 0,73**; Web-XSS 0,83; Bot 0,98; PortScan 0,99. | **Khớp một phần:** 0,734 ↔ 0,73 (Web-BF) và các lớp còn lại lệch ≤0,01. **Sai hai điểm:** (a) Heartbleed/Infiltration **không có** trong bảng gốc; (b) metric gốc là *accuracy từng lớp*, không phải TPR, và họ **bỏ 90% graph benign** trước khi đánh giá ⇒ điều kiện khác nhóm. |
| **Anomal-E**: "HBOS trên CSE-CIC-IDS2018: macro-F1 **86,28 → 94,51** khi dùng embedding thay đặc trưng thô" | Bảng 5 (tr. 10), NF-CSE-CIC-IDS2018-v2, contamination 0%: HBOS raw **86,28%** → embeddings **94,51%** macro-F1. | **Khớp chính xác.** |
| **Table XII**: PBCNN 0,983 TPR / 7,89 µs; PL-RNN 0,564/2,91 µs; HAST-II 0,690/4,2 µs; AEIDS 0,587/2,65 µs; PayloadEmbeddings 0,954/2,73 µs | Không có PDF mở để kiểm tra (Elsevier paywall). | **[THIẾU NGUỒN]** |
| **Table XIII**: SPIN-IDS TPR theo p (81,59 … 98,77) | IEEE TBD 2025, paywall. | **[THIẾU NGUỒN]** |
| **Table XI, dòng GraphDDoS**: TPR 0,956–0,993 | Bài IEEE, không tìm được PDF mở. | **[THIẾU NGUỒN]** |
| **GraphIDS**: PR-AUC ≤ 99,98%, macro-F1 ≤ 99,61% | Không xác định được bài gốc từ trích dẫn của [1]. | **[THIẾU NGUỒN]** |
| **Kitsune**: TPR/FPR/AUC (không trích số cụ thể) | NDSS 2018, trang tải trả HTML; không có số nào được dùng trong báo cáo. | Không ảnh hưởng |

## 2. Cách dùng trong báo cáo

- Mọi số lấy từ bài neo phải giữ nhãn `[1]` (nguồn thứ cấp) **và** ghi chú điều kiện; đặc biệt
  dòng E-GraphSAGE của Table XI **không được** trình bày như số của E-GraphSAGE.
- So sánh định lượng của nhóm (B0/B1/B2/A2/A3/A5/P1, 2018, ACI) không phụ thuộc các số này.
- Khi GVHD hỏi "số này ở đâu ra": trả lời bằng bảng trên (3 PDF trong `docs/related/`, phần còn
  lại là nguồn thứ cấp/paywall).

## 3. Tái lập

```bash
pdftotext -layout docs/related/pujol_perich.pdf - | sed -n '/Table 1/,+16p'
pdftotext -layout docs/related/anomale.pdf     - | sed -n '/Table 5/,+8p'
pdftotext -layout docs/related/egraphsage.pdf  - | grep -n "UNSW-NB15\|ToN-IoT\|BoT-IoT"
```
