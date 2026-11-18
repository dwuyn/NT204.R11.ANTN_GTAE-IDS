# Cross-dataset: CIC-IDS2018 one day + the wait behind "early detection"

**Ngày:** 2026-11-19. **Trạng thái:** đo xong, số liệu ở `results/2018/M1_summary.csv` và `results/wait_p.csv`.
**Phạm vi:** hai mục MAY còn hở — (a) FPR trên môi trường mới, đúng phần paper không đo (test 2018/ACI chỉ có lưu lượng độc hại); (b) thời gian chờ đủ p gói, đúng phần MDT 1,28 µs/gói bỏ qua.
**Nguồn dữ liệu:** `docs/DATA_ACQUISITION.md`; lịch + IP: `configs/cicids2018_schedule.yaml`; xây đồ thị: `scripts/build_cross_dataset_graphs.py`.

---

## 1. Dữ liệu thực tế — những gì capture chứa, không phải những gì lịch ghi

Capture victim-side `UCAP172.31.69.25-part1.pcap` (4,31 GB, 18,9M gói, 12:26–17:58 UTC) sau khi label theo lịch UNB với offset đo được **−240 phút**:

| lớp | số flow | bằng chứng |
|---|---:|---|
| attack `DoS-Hulk` | **1.803.379** | 18.219.193.20 → 172.31.69.25:80, 10 gói/flow, median 0,14 s; cửa sổ lịch 13:45–14:19 local = 17:45–18:19 UTC; capture dừng 17:58 ⇒ **13/34 phút** |
| benign (server) | 847 | ngoài hai cửa sổ |
| UNCERTAIN | 105.576 | **105.550 flow 2 gói, duration 0**, 13.59.126.31 → 172.31.69.25:**21**, đúng cửa sổ SlowHTTPTest nhưng sai cổng ⇒ `service_port_mismatch` |
| benign (5 capture client) | 34.882 | `capPC1-*`, 12:37–21:30 UTC, RDP/SMB/telemetry |

Hai điểm phải nói trước khi đọc số:

1. **Không có SlowHTTPTest trong capture này.** Cửa sổ 10:12–11:08 local chỉ chứa 105.550 lần thử kết nối tới **cổng 21 đã đóng** (2 gói, 0 giây) — đúng hiện tượng Engelen và cộng sự ghi cho ngày 16-02-2018 (*"port 21 of the target system is closed… FTP Patator is not even supposed to be run"*). Nhóm **không** gán chúng là tấn công; chúng bị loại là UNCERTAIN.
2. **Chỉ còn một lớp tấn công** (Hulk) và capture bị cắt giữa cửa sổ. Vì vậy phần này đo "FPR trong môi trường mới" + "TPR trên một flood", không đo được độ phủ 11 lớp như Table VII.

## 2. Protocol một ngày (temporal, không rò rỉ)

`cutoff = 17:45:27Z` = `t_first` của flow tấn công sớm nhất.

| split | nguồn | lấy |
|---|---|---|
| `train1` (5.000) + `train2` (2.000) | benign, `t_first < cutoff`, 6 capture | chia ngẫu nhiên seed 0 |
| `test` benign (5.000) | benign, `t_first ≥ cutoff` | 5 capture client |
| `test` attack (5.000) | `DoS-Hulk` | 1.802.887 flow đủ p=8 |

Bể chọn ở p=8: train 16.905 · test benign 12.240 · attack 1.802.887 (`data/graphs/2018/summary.json`).
Graph: 10.000 edge test, 9.818 nút — hub tấn công (1 attacker → 1 victim, 5.000 cạnh) chi phối line graph; `K_max=32` cắt bớt lân cận của hub.

## 3. Kết quả p = 8 (trung bình 3 seed) — cùng detector, cùng pipeline với 2017

| Detector | 2018 TPR | 2018 FPR | 2018 AUROC | 2018 TPR@1% | 2017 TPR | 2017 FPR | 2017 AUROC |
|---|---:|---:|---:|---:|---:|---:|---:|
| IForest | 5,15% | 1,29% | 0,762 | 6,01% | 3,90% | 2,82% | 0,601 |
| OCSVM | 5,66% | 1,21% | 0,683 | 6,15% | 0,04% | 1,48% | 0,595 |
| HBOS | 6,57% | 1,61% | 0,767 | 6,01% | 7,41% | 3,51% | 0,543 |
| INNE | **16,69%** | 6,15% | **0,812** | **19,53%** | 8,69% | 1,84% | 0,578 |
| Ensemble `tie` | 5,99% | 1,52% | 0,764 | 5,94% | 4,18% | 2,79% | 0,594 |
| Ensemble `strict` | 5,34% | 1,19% | 0,764 | 5,94% | 0,10% | 0,55% | 0,594 |

Đọc bảng:

- **Xếp hạng (AUROC) tốt hơn 2017**: 0,764 vs 0,594, và TPR@1% 5,94% vs 3,65%. Cùng một encoder, cùng 4 detector ⇒ khác biệt đến từ dữ liệu, không từ code.
- **INNE là detector mạnh nhất ở cả hai bộ** (AUROC 0,812 / 0,578) — nhưng ở 2018 nó trả giá bằng FPR 6,15%, gấp 4 lần IForest. Ensemble `tie` lại **thấp hơn** INNE một mình (0,764): bỏ phiếu 2/4 kéo tín hiệu của INNE xuống, đúng vấn đề đã thấy ở Table VI và là động cơ của P1.
- **Không đạt con số nào của paper.** Table VIII của [1] ghi 2018 p=8: **98,74%** TPR (6.012 cạnh, test **chỉ có traffic độc hại**). Con số 5,99% ở đây không phủ định nó — hai bài toán khác nhau: của nhóm có FPR thật (5.000 benign) và ngưỡng do contamination 1% quyết định, của paper không có benign trong test.

## 4. Giới hạn — đọc kèm

1. **Attack và benign đến từ hai nhóm host khác nhau** (flood 1 attacker → 1 server; benign = RDP/SMB/telemetry của 5 PC). Một phần AUROC 0,76 là cấu trúc điểm cuối, không phải nội dung gói. Muốn tách bạch phải có benign cùng host/port — dữ liệu một ngày này không có.
2. **5.000 flow Hulk là mẫu của 1,8M flow gần trùng**; FPR đo trên 5.000 benign từ 5 capture. Không có khoảng tin cậy theo lớp (chỉ 3 seed).
3. **Không có SlowHTTPTest** (mục 1) ⇒ không thể báo per-class như Table VII; 2018 chỉ đóng góp một lớp.
4. Capture bị cắt ở 17:58 ⇒ 13/34 phút của Hulk.

## 5. Wait behind "early detection" (`results/wait_p.csv`)

`wait_p = t_p − t_1`; với flow ngắn hơn p gói, pipeline phải đợi flow đóng để zero-pad ⇒ dùng `delay_p = t_last − t_1`. Đo trên toàn bộ flow 2017 (`T`): 592.554 benign, 438.711 attack, 5 ngày.

| p | benign: đạt p | benign delay median | attack: đạt p | attack wait median | attack delay median | attack delay p95 |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 99,7% | 0,036 s | 99,8% | 0,000 s | 0,000 s | 0,000 s |
| 4 | 90,4% | 0,051 s | 63,2% | 0,008 s | 0,008 s | 1,57 s |
| 6 | 86,3% | 0,101 s | 63,1% | 0,367 s | 0,079 s | 3,76 s |
| 8 | 79,9% | 0,132 s | 61,9% | 0,369 s | 0,079 s | 3,79 s |

Theo lớp tấn công ở p = 8 (median delay / p95):

| lớp | đạt p=8 | delay median | delay p95 |
|---|---:|---:|---:|
| PortScan | **0,1%** | 0,000 s | 0,000 s |
| DoS Hulk | 99,7% | 0,147 s | 1,19 s |
| DDoS | 100% | 0,597 s | 1,82 s |
| DoS GoldenEye | 100% | 6,27 s | 12,5 s |
| DoS slowloris | 55,6% | 3,00 s | 46,5 s |
| DoS Slowhttptest | 26,9% | **63,1 s** | **218 s** |
| FTP-Patator | 100% | 0,008 s | 0,17 s |
| SSH-Patator | 100% | 0,011 s | 0,029 s |

Đọc bảng:

- APD 7,56 gói của P1 không phải "gần như tức thời": **median 0,37 s** để có 8 gói ở lớp flood nhanh, **p95 3,8 s**; với slow-rate là **3–63 s** và đuôi 46–218 s. Con số MDT 1,28 µs/gói của paper **không bao gồm** khoảng này.
- **PortScan gần như không bao giờ có 8 gói** (0,1%): đường TPR theo p ở p=8 đang chấm các flow quét bằng zero-padding sau khi flow đóng, không phải sau 8 gói. Đây là lý do `delay_p` mới là số đúng cho "thời gian đến quyết định".
- Benign cũng chờ: median 0,13 s, p95 10,1 s ở p=8 — FPR không chỉ là tỉ lệ, mà là tỉ lệ × độ trễ.

## 6. Tái chạy

```bash
# 2018: label -> graph -> train -> eval (mỗi bước ~<2 phút trên CPU)
python -m src.label --flows data/processed/2018/flows_f20180216.parquet \
  --schedule configs/cicids2018_schedule.yaml --offset-minutes -240 \
  --out data/processed/2018/flows_f20180216_labeled.parquet --qa reports/qa_labeling_f20180216.json
for n in 1 2 3 4 5; do python -m src.label --flows data/processed/2018/flows_f20180216_c$n.parquet \
  --schedule configs/cicids2018_schedule.yaml --offset-minutes -240 \
  --out data/processed/2018/flows_f20180216_c${n}_labeled.parquet; done
python scripts/build_cross_dataset_graphs.py --ps 2 3 4 5 6 7 8
python scripts/train_all.py --graphs data/graphs/2018 --out experiments/2018 --ps 8 --seeds 0 1 2 --device cpu
python -m src.eval --models experiments/2018 --graphs data/graphs/2018 --out results/2018 --ps 8 --seeds 0 1 2 --device cpu

# wait_p (3 giây)
python scripts/eval_wait_p.py --out results/wait_p.csv
```
