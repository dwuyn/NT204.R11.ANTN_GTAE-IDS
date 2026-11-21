# Paper-parity: P_paper và T ở đúng điểm vận hành của paper

**Trạng thái:** sinh tự động bởi `scripts/eval_paper_parity.py`; không sửa tay.

**Nguồn số liệu:** `results/paper_parity/*.csv`, `results/P_paper_counts.csv`, `data/graphs/P_paper/summary.json`.

**Thiết lập:** p = 2, 3 seed, contamination grid [0.001, 0.01, 0.04, 0.05, 0.1], điểm vận hành mục tiêu FPR = 6,56% (paper Table VI).

## 1. Thành phần tập test (paper Table II/VII, p = 2)

| tập test | edge | node | benign | PortScan | Heartbleed | Infiltration | DoS Hulk |
|---|---:|---:|---:|---:|---:|---:|---:|
| paper | 33228 | 40744 | 5000 | 6451 | 1468 | 1764 | 5000 |
| P_paper | 30041 | 22328 | 5000 | 6451 | 11 | 34 | 5000 |
| T | 42362 | 25663 | 5000 | 5000 | 1 | 8 | 5000 |
| T_fixed | 30907 | 24030 | 5000 | 204 | 1 | 4 | 5000 |
| ACI | 20000 | 19514 | 5000 | 5000 | 0 | 0 | 0 |

Paper Table VII cần 1.468 edge Heartbleed và 1.764 edge Infiltration. CSV CICFlowMeter chỉ có 11 và 36 dòng flow TCP cho hai nhãn này, nên không cách dựng nào từ CSV đạt được các con số đó (protocol `T` dựng từ pcap được 1 và 4). Đây là phát hiện về cách dựng dữ liệu của paper, không phải lỗi build: `scripts/check_paper_counts.py` ghi nhận là `csv_pool_exhausted`.

### 1b. Đối chiếu Table II (nút, cạnh) — built vs paper

Sinh bởi `scripts/check_paper_counts.py --all-p`; node chỉ để tham chiếu.

| p | split | node built | node paper | cạnh built | cạnh paper |
|---:|---|---:|---:|---:|---:|
| 2 | train1 | 7178 | 7160 | 5000 | 5000 |
| 2 | train2 | 3105 | 3736 | 2000 | 2000 |
| 2 | test | 22328 | 44767 | 30041 | 38984 |
| 3 | train1 | 7178 | 7144 | 5000 | 5000 |
| 3 | train2 | 3105 | 3351 | 2000 | 2000 |
| 3 | test | 22328 | 46285 | 30041 | 37971 |
| 4 | train1 | 7178 | 7135 | 5000 | 5000 |
| 4 | train2 | 3105 | 3145 | 2000 | 2000 |
| 4 | test | 22328 | 45008 | 30041 | 36964 |
| 5 | train1 | 7178 | 7135 | 5000 | 5000 |
| 5 | train2 | 3105 | 3143 | 2000 | 2000 |
| 5 | test | 22328 | 44118 | 30041 | 36093 |
| 6 | train1 | 7178 | 7129 | 5000 | 5000 |
| 6 | train2 | 3105 | 3136 | 2000 | 2000 |
| 6 | test | 22328 | 43417 | 30041 | 35482 |
| 7 | train1 | 7178 | 7112 | 5000 | 5000 |
| 7 | train2 | 3105 | 3126 | 2000 | 2000 |
| 7 | test | 22328 | 41643 | 30041 | 33974 |
| 8 | train1 | 7178 | 7023 | 5000 | 5000 |
| 8 | train2 | 3105 | 3106 | 2000 | 2000 |
| 8 | test | 22328 | 40744 | 30041 | 33228 |

Hai khác biệt đã biết, không phải lỗi build: (i) `P_paper` **zero-pad** flow ngắn nên số cạnh test không đổi theo p (30.041), trong khi cạnh test của paper giảm 38.984 → 33.228, tức paper dựng lại tập test theo từng p với điều kiện `n_pkts >= p`; (ii) node test của nhóm ít hơn (22.328 vs 40.744) vì cùng một endpoint dịch vụ lặp lại trên nhiều flow, trong khi paper đếm nhiều endpoint nguồn tạm thời hơn trên cùng số cạnh.

### 1c. Per-class p = 8: P_paper so với paper Table VII

Cùng cấu hình đã chọn (contamination theo calibration benign) và cùng luật vote; cột `paper` là Table VII của bài báo.

| lớp | paper TPR | P_paper (luật or) | P_paper (luật tie) |
|---|---:|---:|---:|
| DDoS | 99.34% | 9,23 | 0,61 |
| DoS GoldenEye | 99.08% | 7,65 | 0,75 |
| DoS Hulk | 98.74% | 7,57 | 0,58 |
| DoS Slowhttptest | 99.79% | 6,43 | 0,76 |
| DoS Slowloris | 99.60% | 8,55 | 2,00 |
| FTP-Patator | 98.85% | 6,32 | 1,72 |
| Heartbleed | 99.52% | 33,33 | 0,00 |
| Infiltration | 99.83% | 0,98 | 0,98 |
| PortScan | 98.50% | 28,56 | 25,31 |
| SSH-Patator | 98.86% | 5,52 | 0,19 |
| Web Attack - Brute Force | 99.29% | 5,71 | 0,48 |
## 2. Điểm vận hành (FPR mục tiêu 6,56%)

Ba cách đặt ngưỡng, cùng một embedding:

1. **ngưỡng riêng của detector**: `contamination` quyết định ngưỡng nội bộ; `FPR@ngưỡng riêng` là FPR thực trên test.
2. **quantile calibration**: ngưỡng = phân vị `1 - FPR` của điểm benign trên split calibration (400 flow `train2`); cho thấy ảnh hưởng lệch phân phối.
3. **matched test FPR**: ngưỡng = phân vị sao cho FPR thực trên benign test đúng bằng 6,56%; đây là cột so sánh trực tiếp với paper.

| thiết lập | luật | contamination | FPR@ngưỡng riêng | TPR@FPR 6,56% (quantile calibration) | TPR@FPR 6,56% (matched test FPR) | TPR@FPR 1% (matched test FPR) | AUROC |
|---|---|---:|---:|---:|---:|---:|---:|
| paper Table VI (p=8, FPR 6,56%) | n/a | n/a | 6,56 | n/a | 99,04 | n/a | n/a |
| P_paper (mean 3 seed) | strict | 0,067 | 4,59 | 2,99 | 3,79 | 0,21 | 0,4287 |
| P_paper (mean 3 seed) | tie | 0,050 | 4,93 | 2,99 | 3,79 | 0,21 | 0,4287 |
| P_paper (mean 3 seed) | or | 0,040 | 6,87 | 2,99 | 3,79 | 0,21 | 0,4287 |
| P_paper (mean 3 seed) | IForest | 0,047 | 4,58 | 3,23 | 3,77 | 0,18 | 0,4260 |
| P_paper (mean 3 seed) | OCSVM | 0,050 | 4,83 | 1,24 | 1,47 | 0,22 | 0,4145 |
| P_paper (mean 3 seed) | HBOS | 0,050 | 4,98 | 4,80 | 5,09 | 0,23 | 0,4465 |
| P_paper (mean 3 seed) | INNE | 0,050 | 5,11 | 5,06 | 4,98 | 0,25 | 0,4591 |
| T (mean 3 seed) | strict | 0,100 | 22,49 | 26,76 | 10,22 | 1,15 | 0,5054 |
| T (mean 3 seed) | tie | 0,047 | 19,98 | 26,76 | 10,22 | 1,15 | 0,5054 |
| T (mean 3 seed) | or | 0,050 | 21,75 | 26,76 | 10,22 | 1,15 | 0,5054 |
| T (mean 3 seed) | IForest | 0,083 | 22,06 | 25,52 | 9,95 | 1,11 | 0,5003 |
| T (mean 3 seed) | OCSVM | 0,050 | 20,26 | 26,17 | 13,05 | 1,46 | 0,5205 |
| T (mean 3 seed) | HBOS | 0,067 | 20,11 | 24,18 | 5,16 | 0,37 | 0,4826 |
| T (mean 3 seed) | INNE | 0,050 | 21,13 | 29,10 | 12,67 | 3,18 | 0,5164 |

## 3. Chi tiết theo seed (contamination đã chọn)

### P_paper

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | IForest | 0,050 | 2,16 | 5,92 | 2,60 | 0,26 |
| 0 | OCSVM | 0,050 | 2,09 | 5,92 | 2,44 | 0,19 |
| 0 | HBOS | 0,050 | 2,72 | 4,90 | 4,20 | 0,41 |
| 0 | INNE | 0,050 | 2,52 | 7,08 | 2,35 | 0,17 |
| 0 | strict | 0,050 | 2,61 | 6,14 | 2,95 | 0,28 |
| 0 | tie | 0,050 | 2,61 | 6,14 | 2,95 | 0,28 |
| 0 | or | 0,040 | 2,61 | 6,14 | 2,95 | 0,28 |
| 1 | IForest | 0,040 | 3,08 | 7,30 | 2,58 | 0,28 |
| 1 | OCSVM | 0,050 | 0,96 | 5,82 | 1,11 | 0,28 |
| 1 | HBOS | 0,050 | 1,53 | 6,78 | 1,39 | 0,28 |
| 1 | INNE | 0,050 | 10,81 | 7,72 | 8,93 | 0,28 |
| 1 | strict | 0,100 | 1,41 | 5,28 | 2,58 | 0,28 |
| 1 | tie | 0,050 | 1,41 | 5,28 | 2,58 | 0,28 |
| 1 | or | 0,040 | 1,41 | 5,28 | 2,58 | 0,28 |
| 2 | IForest | 0,050 | 4,44 | 5,32 | 6,13 | 0,00 |
| 2 | OCSVM | 0,050 | 0,66 | 5,92 | 0,85 | 0,18 |
| 2 | HBOS | 0,050 | 10,16 | 8,24 | 9,70 | 0,00 |
| 2 | INNE | 0,050 | 1,83 | 4,84 | 3,66 | 0,30 |
| 2 | strict | 0,050 | 4,94 | 5,86 | 5,83 | 0,06 |
| 2 | tie | 0,050 | 4,94 | 5,86 | 5,83 | 0,06 |
| 2 | or | 0,040 | 4,94 | 5,86 | 5,83 | 0,06 |

### T

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | IForest | 0,100 | 27,56 | 22,86 | 5,36 | 0,38 |
| 0 | OCSVM | 0,050 | 27,74 | 23,72 | 7,76 | 0,75 |
| 0 | HBOS | 0,100 | 26,11 | 22,84 | 6,50 | 0,88 |
| 0 | INNE | 0,050 | 32,63 | 23,86 | 7,05 | 5,92 |
| 0 | strict | 0,100 | 29,67 | 23,68 | 7,72 | 0,59 |
| 0 | tie | 0,050 | 29,67 | 23,68 | 7,72 | 0,59 |
| 0 | or | 0,050 | 29,67 | 23,68 | 7,72 | 0,59 |
| 1 | IForest | 0,100 | 25,20 | 21,46 | 13,57 | 1,90 |
| 1 | OCSVM | 0,050 | 26,64 | 22,36 | 15,77 | 2,36 |
| 1 | HBOS | 0,050 | 23,33 | 20,58 | 4,45 | 0,11 |
| 1 | INNE | 0,050 | 28,04 | 23,72 | 22,15 | 3,44 |
| 1 | strict | 0,100 | 26,55 | 22,22 | 13,24 | 1,68 |
| 1 | tie | 0,040 | 26,55 | 22,22 | 13,24 | 1,68 |
| 1 | or | 0,050 | 26,55 | 22,22 | 13,24 | 1,68 |
| 2 | IForest | 0,050 | 23,81 | 21,40 | 10,92 | 1,04 |
| 2 | OCSVM | 0,050 | 24,14 | 21,38 | 15,63 | 1,25 |
| 2 | HBOS | 0,050 | 23,08 | 19,84 | 4,54 | 0,12 |
| 2 | INNE | 0,050 | 26,62 | 22,72 | 8,81 | 0,18 |
| 2 | strict | 0,100 | 24,07 | 21,18 | 9,70 | 1,17 |
| 2 | tie | 0,050 | 24,07 | 21,18 | 9,70 | 1,17 |
| 2 | or | 0,050 | 24,07 | 21,18 | 9,70 | 1,17 |


## 3b. Đường cong p (paper Table VI)

Cùng cách chọn contamination theo calibration benign, lặp cho từng p. Cột `matched` đặt ngưỡng sao cho FPR thực trên benign test đúng 6,56%, nên so được với Table VI; `paper` là số của paper.

| p | paper TPR@FPR 6,56% | P_paper OR TPR@6,56% | P_paper tie TPR@6,56% | P_paper AUROC | T OR TPR@6,56% | T AUROC |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 84.47 / 8.94 % | 3,79 | 3,79 | 0,4332 | 10,22 | 0,5052 |
| 3 | 91.02 / 7.61 % | 12,47 | 12,47 | 0,5661 | 8,37 | 0,5054 |
| 4 | 94.72 / 6.60 % | 5,36 | 5,36 | 0,4728 | 19,67 | 0,5773 |
| 5 | 97.16 / 6.84 % | 1,10 | 1,10 | 0,4243 | 11,48 | 0,6327 |
| 6 | 98.44 / 6.73 % | 5,40 | 5,40 | 0,4114 | 33,77 | 0,8011 |
| 7 | 98.72 / 5.91 % | 26,77 | 26,77 | 0,5346 | 19,99 | 0,6904 |
| 8 | 99.04 / 6.56 % | 3,25 | 3,25 | 0,4785 | 11,54 | 0,5854 |


## 4. Chẩn đoán zero-pad (AUROC, IForest contamination 0,05)

Chẩn đoán, không phải điểm vận hành: tách AUROC theo số gói tin thực của edge test để kiểm tra liệu edge zero-pad có tạo ra khả năng phân biệt giả.

| protocol | seed | tập con | edge tấn công | edge benign | AUROC |
|---|---:|---|---:|---:|---:|
| P_paper | 0 | all_edges | 25041 | 5000 | 0,5091 |
| P_paper | 0 | full_2_packets | 25038 | 5000 | 0,5090 |
| P_paper | 0 | padded_attacks | 3 | 5000 | 0,7945 |
| P_paper | 1 | all_edges | 25041 | 5000 | 0,3859 |
| P_paper | 1 | full_2_packets | 25038 | 5000 | 0,3859 |
| P_paper | 1 | padded_attacks | 3 | 5000 | 0,8801 |
| P_paper | 2 | all_edges | 25041 | 5000 | 0,3829 |
| P_paper | 2 | full_2_packets | 25038 | 5000 | 0,3828 |
| P_paper | 2 | padded_attacks | 3 | 5000 | 0,9754 |
| T | 0 | all_edges | 37362 | 5000 | 0,5182 |
| T | 0 | full_2_packets | 37362 | 5000 | 0,5182 |
| T | 0 | padded_attacks | 0 | 5000 | n/a |
| T | 1 | all_edges | 37362 | 5000 | 0,4949 |
| T | 1 | full_2_packets | 37362 | 5000 | 0,4949 |
| T | 1 | padded_attacks | 0 | 5000 | n/a |
| T | 2 | all_edges | 37362 | 5000 | 0,4877 |
| T | 2 | full_2_packets | 37362 | 5000 | 0,4877 |
| T | 2 | padded_attacks | 0 | 5000 | n/a |

## 5. Kết luận

`P_paper` đạt 3,25% TPR ở FPR matched 6,56% với luật OR của code tác giả (luật tie: 3,25%; cả ba luật vote cho cùng TPR vì dùng chung score fusion). Detector tốt nhất (IForest) đạt 8,90%. Trên cùng pipeline, protocol `T` sạch (luật tie) đạt 11,54%. So với 99,04% của paper, khoảng cách vẫn hơn 60 điểm phần trăm. Khớp thành phần tập test (Table VII), grid contamination (Table V) và luật OR của code tác giả **không** thu hẹp khoảng cách, nên kết quả âm của bản tái hiện là bền vững theo cách dựng dữ liệu: con số ~99% không tái lập được từ artefact công khai dưới cả hai định nghĩa flow.
