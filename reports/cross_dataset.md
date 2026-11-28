# Cross-dataset: CIC-IDS2018 + ACI-IoT-2023 và chi phí chờ của "early detection"

**Ngày:** 2026-11-19 (2018, wait) và 2026-11-21 (ACI). **Trạng thái:** đo xong; số liệu ở `results/2018/`, `results/aci/`, `results/wait_p.csv`.
**Phạm vi:** ba mục MAY - (a) FPR trên CIC-IDS2018 một ngày; (b) FPR trên ACI-IoT-2023 với benign **ngày khác**; (c) thời gian chờ đủ p gói, phần mà MDT 1,28 µs/gói bỏ qua.
**Nguồn dữ liệu:** `docs/DATA_ACQUISITION.md`; lịch + IP: `configs/cicids2018_schedule.yaml`; xây đồ thị: `scripts/build_cross_dataset_graphs.py`.

---

## 1. Dữ liệu thực tế - những gì capture chứa, không phải những gì lịch ghi

Capture victim-side `UCAP172.31.69.25-part1.pcap` (4,31 GB, 18,9M gói, 12:26-17:58 UTC) sau khi label theo lịch UNB với offset đo được **−240 phút**:

| lớp | số flow | bằng chứng |
|---|---:|---|
| attack `DoS-Hulk` | **1.803.379** | 18.219.193.20 → 172.31.69.25:80, 10 gói/flow, median 0,14 s; cửa sổ lịch 13:45-14:19 local = 17:45-18:19 UTC; capture dừng 17:58 ⇒ **13/34 phút** |
| benign (server) | 847 | ngoài hai cửa sổ |
| UNCERTAIN | 105.576 | **105.550 flow 2 gói, duration 0**, 13.59.126.31 → 172.31.69.25:**21**, đúng cửa sổ SlowHTTPTest nhưng sai cổng ⇒ `service_port_mismatch` |
| benign (5 capture client) | 34.882 | `capPC1-*`, 12:37-21:30 UTC, RDP/SMB/telemetry |

Hai điểm phải nói trước khi đọc số:

1. **Không có SlowHTTPTest trong capture này.** Cửa sổ 10:12-11:08 local chỉ chứa 105.550 lần thử kết nối tới **cổng 21 đã đóng** (2 gói, 0 giây) - đúng hiện tượng Engelen và cộng sự ghi cho ngày 16-02-2018 (*"port 21 of the target system is closed… FTP Patator is not even supposed to be run"*). Nhóm **không** gán chúng là tấn công; chúng bị loại là UNCERTAIN.
2. **Chỉ còn một lớp tấn công** (Hulk) và capture bị cắt giữa cửa sổ. Vì vậy phần này đo "FPR trong môi trường mới" + "TPR trên một flood", không đo được độ phủ 11 lớp như Table VII.

## 2. Protocol một ngày (temporal, không rò rỉ)

`cutoff = 17:45:27Z` = `t_first` của flow tấn công sớm nhất.

| split | nguồn | lấy |
|---|---|---|
| `train1` (5.000) + `train2` (2.000) | benign, `t_first < cutoff`, 6 capture | chia ngẫu nhiên seed 0 |
| `test` benign (5.000) | benign, `t_first ≥ cutoff` | 5 capture client |
| `test` attack (5.000) | `DoS-Hulk` | 1.802.887 flow đủ p=8 |

Bể chọn ở p=8: train 16.905 · test benign 12.240 · attack 1.802.887 (`data/graphs/2018/summary.json`).
Graph: 10.000 edge test, 9.818 nút - hub tấn công (1 attacker → 1 victim, 5.000 cạnh) chi phối line graph; `K_max=32` cắt bớt lân cận của hub.

## 3. Kết quả p = 8 (trung bình 3 seed) - cùng detector, cùng pipeline với 2017

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
- **INNE là detector mạnh nhất ở cả hai bộ** (AUROC 0,812 / 0,578) - nhưng ở 2018 nó trả giá bằng FPR 6,15%, gấp 4 lần IForest. Ensemble `tie` lại **thấp hơn** INNE một mình (0,764): bỏ phiếu 2/4 kéo tín hiệu của INNE xuống, đúng vấn đề đã thấy ở Table VI và là động cơ của P1.
- **Không đạt con số nào của paper.** Table VIII của [1] ghi 2018 p=8: **98,74%** TPR (6.012 cạnh, test **chỉ có traffic độc hại**). Con số 5,99% ở đây không phủ định nó - hai bài toán khác nhau: của nhóm có FPR thật (5.000 benign) và ngưỡng do contamination 1% quyết định, của paper không có benign trong test.

### 3.1 Đường cong p = 2…8 (3 seed mỗi p)

| p | ensemble `tie` TPR | FPR | AUROC | TPR@1% | INNE AUROC | paper Table VIII |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 4,35% | 1,57% | 0,278 | 3,56% | 0,320 | 81,63% |
| 3 | 3,04% | 1,36% | 0,542 | 3,41% | 0,530 | 91,27% |
| 4 | 1,32% | 1,15% | 0,612 | 3,65% | 0,638 | 93,67% |
| 5 | 9,13% | 1,53% | 0,576 | 8,56% | 0,594 | 97,05% |
| 6 | 3,36% | 1,62% | 0,523 | 6,34% | 0,658 | 98,51% |
| 7 | 2,32% | 1,02% | 0,607 | 2,03% | 0,701 | 98,65% |
| 8 | 5,99% | 1,52% | **0,764** | 5,94% | **0,812** | 98,74% |

- **Không tái hiện được xu hướng tăng đơn điệu** của paper (81,6 → 98,7). AUROC dao động 0,28-0,76 và chỉ ở p=8 mới vượt 0,7. Ở p=2 AUROC **0,278** - xếp hạng *ngược*: với 2 gói đầu, flow flood (SYN + SYN-ACK) có lỗi tái tạo thấp hơn benign 2 gói (RDP/SMB đóng sớm) nên detector chấm attack là "bình thường".
- Kết luận trung thực cho 2018: chỉ p=8 đo được tín hiệu (AUROC 0,76; INNE 0,81), và ngay cả khi đó TPR@FPR=1% chỉ 5,9-19,5% - không có "vài gói đầu là đủ" trong môi trường mới với FPR thật.

## 4. Giới hạn - đọc kèm

1. **Attack và benign đến từ hai nhóm host khác nhau** (flood 1 attacker → 1 server; benign = RDP/SMB/telemetry của 5 PC). Một phần AUROC 0,76 là cấu trúc điểm cuối, không phải nội dung gói. Muốn tách bạch phải có benign cùng host/port - dữ liệu một ngày này không có.
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

Các cột delay ở trên là **trung vị của trung vị theo ngày** (mỗi ngày một trung vị, rồi lấy
trung vị 5 ngày). Gộp theo **flow** (`results/wait_p_pooled.csv`) cho con số khác: benign
0,033/0,040/0,085/0,102 s và attack 0,000/0,002/0,053/0,056 s cho p=2/4/6/8; p95 attack
1,00/1,00/1,84/1,86 s. Báo cáo dùng bản gộp theo flow; bảng này giữ bản theo ngày để so
với cách tổng hợp trước đó.

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

- APD 7,56 gói của P1 không phải "gần như tức thời": **median 0,37 s** để có 8 gói ở lớp flood nhanh, **p95 3,8 s**; với slow-rate là **3-63 s** và đuôi 46-218 s. Con số MDT 1,28 µs/gói của paper **không bao gồm** khoảng này.
- **PortScan gần như không bao giờ có 8 gói** (0,1%): đường TPR theo p ở p=8 đang chấm các flow quét bằng zero-padding sau khi flow đóng, không phải sau 8 gói. Đây là lý do `delay_p` mới là số đúng cho "thời gian đến quyết định".
- Benign cũng chờ: median 0,13 s, p95 10,1 s ở p=8 - FPR không chỉ là tỉ lệ, mà là tỉ lệ × độ trễ.

## 6. ACI-IoT-2023 - benign ngày khác, ba lớp TCP (đối chiếu Table VIII/IX)

**Dữ liệu.** 2.352 capture ACI (wired + wireless) đã merge hợp lệ per lớp
(`scripts/merge_pcaps.py`; `cat` thường làm parser dừng sau file đầu) rồi parse:
benign 31/10 (9.346 benign), benign 3/11 (14.992), PortScan 30/10 (**426.795** flow -
97,8% so với 436.502 dòng TCP của ACI), Slowloris 1/11 (9.428), Dictionary-Brute-Force
2/11 (5.466). Đồng hồ capture **nhanh hơn 4 giờ** so với tên file/README: file
`2023-10-31-09_02_06_wireless.pcap` bắt đầu ở epoch 1698757326 = **13:02:06 UTC**;
`configs/aci_iot2023_schedule.yaml` ghi `utc_offset_minutes: -240` (đo, không đoán -
lần đọc sai đầu tiên cho 0 tấn công).

**Protocol.** Label theo cửa sổ (README không có IP attacker), train trên benign 31/10,
test = benign **ngày khác** 3/11 (5.000) + 5.000 mỗi lớp tấn công. PortScan vẫn còn
5.986 flow ≥ 8 gói nên cả ba lớp sống tới p=8. 68.208 flow bị loại là bản trùng của hai
sniffer (cùng 5-tuple, lệch ≤ 0,5 s).

**Cảnh báo đọc số.** Benign *trong* cửa sổ tấn công bị gán attack (không có IP để tách)
⇒ TPR là **cận trên**; FPR đo trên ngày benign còn lại nên vẫn là số thật.

| p | paper Table VIII (ACI, tổng) | ACI ensemble `tie` TPR | FPR | AUROC | TPR@1% |
|---:|---:|---:|---:|---:|---:|
| 2 | 79,02% | 2,68% | 0,86% | 0,564 | 1,64% |
| 3 | 88,94% | 1,23% | 0,77% | **0,428** | 1,10% |
| 4 | 93,21% | 1,78% | 0,87% | 0,477 | 1,62% |
| 5 | 94,87% | 1,65% | 1,23% | 0,483 | 1,66% |
| 6 | 96,76% | 2,40% | 0,97% | 0,536 | 2,17% |
| 7 | 97,88% | 1,76% | 1,70% | 0,550 | 2,45% |
| 8 | 98,21% | 1,69% | 1,11% | 0,536 | 1,95% |

p=8 từng detector: IForest 0,537 · OCSVM 0,530 · HBOS 0,529 · INNE 0,540 AUROC
(TPR@1%: 1,95 / 1,43 / 1,92 / 0,63%). Không detector nào vượt 0,55.

p=8 theo lớp (ensemble `tie`, 3 seed) đặt cạnh paper **Table IX** (cùng p=8):

| lớp | paper Table IX | nhóm |
|---|---:|---:|
| Port Scan | 99,67% | **2,66%** |
| DoS Slowloris | 99,56% | **1,76%** |
| Dictionary Brute Force | - (không có trong Table IX) | **0,66%** |
| ICMP Flooding | 96,54% | - (ngoài scope TCP) |
| Ping Sweep | 99,19% | - (ICMP, ngoài scope) |
| ARP Spoofing | 97,31% | - (không phải IP/TCP) |

Hai lớp giao nhau (PortScan, Slowloris) cách paper ~97 điểm phần trăm; ba lớp còn lại của
paper nằm ngoài scope TCP của nhóm nên không so được, và lớp Dictionary của nhóm không có
trong Table IX.

Ở khung paper-parity (`scripts/eval_paper_parity.py`, cùng grid contamination, ngưỡng đặt sao cho
FPR thực trên benign 3/11 đúng **6,56%** như paper): ACI ensemble `tie` TPR **8,03%**, AUROC
**0,536**, TPR@1% 1,85% - vẫn cách 98,21% của paper hơn 90 điểm phần trăm. Hai cách đặt ngưỡng
(contamination 1% của `src.eval` và matched 6,56% của parity) đều cho cùng kết luận.

Đọc bảng:

- **Không có tín hiệu chuyển miền.** AUROC 0,43-0,56 ở mọi p, tức quanh mức đoán mò; p=3 còn *dưới* 0,5.
  Con số 79,02-98,21% của paper là test **chỉ có lưu lượng độc hại** trong cùng môi trường; khi bắt buộc
  phải tách khỏi benign của **ngày khác**, cùng pipeline không tách được.
- **Đây không phải lỗi nhãn:** nhãn đã đối chiếu số lượng với chính ACI (PortScan 426.795 ≈ 436.502 dòng TCP),
  và FPR đo trên 5.000 flow benign thật của ngày 3/11. Nhưng nó cũng **không** phải phép thử công bằng hoàn hảo:
  benign *trong* cửa sổ tấn công bị gán attack (không có IP), và benign ngày 3/11 đến từ thiết bị/hoạt động
  khác ngày 31/10 ⇒ đây là **domain shift theo ngày**, đúng thứ paper không đo.
- So sánh có ý nghĩa nhất là với 2018 (cùng pipeline, cùng cách đo FPR): 2018 AUROC 0,764 ở p=8,
  ACI 0,536 - môi trường IoT khó hơn hẳn khi benign đổi ngày.

## 7. Tái chạy

```bash
# 2018: label -> graph -> train (p2..7: 6m30s; p8: 1m38s) -> eval (1m15s), all CPU
python -m src.label --flows data/processed/2018/flows_f20180216.parquet \
  --schedule configs/cicids2018_schedule.yaml --offset-minutes -240 \
  --out data/processed/2018/flows_f20180216_labeled.parquet --qa reports/qa_labeling_f20180216.json
for n in 1 2 3 4 5; do python -m src.label --flows data/processed/2018/flows_f20180216_c$n.parquet \
  --schedule configs/cicids2018_schedule.yaml --offset-minutes -240 \
  --out data/processed/2018/flows_f20180216_c${n}_labeled.parquet; done
python scripts/build_cross_dataset_graphs.py --ps 2 3 4 5 6 7 8
python scripts/train_all.py --graphs data/graphs/2018 --out experiments/2018 --ps 8 --seeds 0 1 2 --device cpu
python -m src.eval --models experiments/2018 --graphs data/graphs/2018 --out results/2018 --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --device cpu

# wait_p (3 giây)
python scripts/eval_wait_p.py --out results/wait_p.csv

# P_paper p-curve (Table VI): build all p once (reads 51 GB pcap), train p2..7, eval grid
python scripts/build_paper_graphs.py --out data/graphs/P_paper --ps 2 3 4 5 6 7 8 --seed 0
python scripts/train_all.py --graphs data/graphs/P_paper --out experiments/P_paper --ps 2 3 4 5 6 7 --seeds 0 1 2 --device cpu
python scripts/eval_paper_parity.py --protocols P_paper T ACI --ps 2 3 4 5 6 7 8 \
  --seeds 0 1 2 --out results/paper_parity --device cpu --write-report --diagnostics
python scripts/check_paper_counts.py --all-p      # results/P_paper_table2.csv

# ACI: merge valid pcaps -> parse -> label -> graphs -> train -> eval
for spec in "Benign Pcaps|2023-10-31-*|benign1" "Benign Pcaps|2023-11-03-*|benign2" \
            "Recon Pcaps|*.pcap|recon" "Brute Force Pcaps|*.pcap|brute" "DoS_Pcaps|*.pcap|slowloris"; do
  IFS='|' read -r inc glob tag <<< "$spec"
  python scripts/merge_pcaps.py --include "$inc" --glob "$glob" --out "data/raw/aci/merged/$tag.pcap"
  python -m src.parse_pcap --pcap "data/raw/aci/merged/$tag.pcap" --out data/processed/aci --day "aci_$tag"
done
python scripts/label_aci.py
python scripts/build_cross_dataset_graphs.py --processed data/processed/aci --out data/graphs/aci \
  --tags aci_benign1 aci_benign2 aci_recon aci_brute aci_slowloris \
  --train-tags aci_benign1 --test-benign-tags aci_benign2 --ps 2 3 4 5 6 7 8
python scripts/train_all.py --graphs data/graphs/aci --out experiments/aci --ps 2 3 4 5 6 7 8 --device cpu
python -m src.eval --models experiments/aci --graphs data/graphs/aci --out results/aci \
  --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --device cpu
```
