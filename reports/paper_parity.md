# Paper-parity: P_paper và T ở đúng điểm vận hành của paper

**Trạng thái:** sinh tự động bởi `scripts/eval_paper_parity.py`; không sửa tay.

**Nguồn số liệu:** `results/paper_parity/*.csv`, `results/P_paper_counts.csv`, `data/graphs/P_paper/summary.json`.

**Thiết lập:** p = 8, 3 seed, contamination grid [0.001, 0.01, 0.04, 0.05, 0.1], điểm vận hành mục tiêu FPR = 6,56% (paper Table VI).

## 1. Thành phần tập test (paper Table II/VII, p = 8)

| tập test | edge | node | benign | PortScan | Heartbleed | Infiltration | DoS Hulk |
|---|---:|---:|---:|---:|---:|---:|---:|
| paper | 33228 | 40744 | 5000 | 6451 | 1468 | 1764 | 5000 |
| P_paper | 30041 | 22328 | 5000 | 6451 | 11 | 34 | 5000 |
| T | 30907 | 24030 | 5000 | 204 | 1 | 4 | 5000 |
| T_fixed | 30907 | 24030 | 5000 | 204 | 1 | 4 | 5000 |

Paper Table VII cần 1.468 edge Heartbleed và 1.764 edge Infiltration. CSV CICFlowMeter chỉ có 11 và 36 dòng flow TCP cho hai nhãn này, nên không cách dựng nào từ CSV đạt được các con số đó (protocol `T` dựng từ pcap được 1 và 4). Đây là phát hiện về cách dựng dữ liệu của paper, không phải lỗi build: `scripts/check_paper_counts.py` ghi nhận là `csv_pool_exhausted`.

## 2. Điểm vận hành (FPR mục tiêu 6,56%)

Ba cách đặt ngưỡng, cùng một embedding:

1. **ngưỡng riêng của detector**: `contamination` quyết định ngưỡng nội bộ; `FPR@ngưỡng riêng` là FPR thực trên test.
2. **quantile calibration**: ngưỡng = phân vị `1 - FPR` của điểm benign trên split calibration (400 flow `train2`); cho thấy ảnh hưởng lệch phân phối.
3. **matched test FPR**: ngưỡng = phân vị sao cho FPR thực trên benign test đúng bằng 6,56%; đây là cột so sánh trực tiếp với paper.

| thiết lập | luật | contamination | FPR@ngưỡng riêng | TPR@FPR 6,56% (quantile calibration) | TPR@FPR 6,56% (matched test FPR) | TPR@FPR 1% (matched test FPR) | AUROC |
|---|---|---:|---:|---:|---:|---:|---:|
| paper Table VI (p=8, FPR 6,56%) | n/a | n/a | 6,56 | n/a | 99,04 | n/a | n/a |
| P_paper (mean 3 seed) | strict | 0,080 | 6,41 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | tie | 0,050 | 6,00 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | or | 0,040 | 8,41 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | IForest | 0,050 | 5,19 | 8,54 | 8,90 | 0,96 | 0,5185 |
| P_paper (mean 3 seed) | OCSVM | 0,047 | 4,53 | 3,10 | 2,95 | 1,50 | 0,3880 |
| P_paper (mean 3 seed) | HBOS | 0,047 | 4,27 | 5,97 | 5,99 | 5,05 | 0,4183 |
| P_paper (mean 3 seed) | INNE | 0,050 | 6,44 | 11,94 | 8,31 | 4,12 | 0,5897 |
| T (mean 3 seed) | strict | 0,067 | 9,59 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | tie | 0,047 | 9,31 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | or | 0,040 | 9,70 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | IForest | 0,047 | 9,18 | 24,33 | 15,75 | 2,11 | 0,6010 |
| T (mean 3 seed) | OCSVM | 0,047 | 8,68 | 22,45 | 8,80 | 0,04 | 0,5951 |
| T (mean 3 seed) | HBOS | 0,043 | 7,77 | 42,35 | 12,27 | 6,53 | 0,5427 |
| T (mean 3 seed) | INNE | 0,040 | 7,97 | 23,37 | 21,21 | 4,80 | 0,5778 |

## 3. Chi tiết theo seed (contamination đã chọn)

### P_paper

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | HBOS | 0,050 | 0,97 | 15,74 | 0,97 | 0,06 |
| 0 | IForest | 0,050 | 1,41 | 10,62 | 0,78 | 0,10 |
| 0 | INNE | 0,050 | 11,53 | 9,62 | 1,19 | 0,14 |
| 0 | OCSVM | 0,050 | 1,31 | 9,96 | 0,85 | 0,08 |
| 0 | or | 0,040 | 1,43 | 9,70 | 0,83 | 0,06 |
| 0 | strict | 0,100 | 1,43 | 9,70 | 0,83 | 0,06 |
| 0 | tie | 0,050 | 1,43 | 9,70 | 0,83 | 0,06 |
| 1 | HBOS | 0,040 | 16,84 | 24,60 | 16,84 | 15,07 |
| 1 | IForest | 0,050 | 24,03 | 6,14 | 25,68 | 2,77 |
| 1 | INNE | 0,050 | 17,66 | 11,42 | 16,85 | 8,82 |
| 1 | OCSVM | 0,040 | 7,99 | 6,48 | 7,99 | 4,44 |
| 1 | or | 0,040 | 8,00 | 6,58 | 8,00 | 4,09 |
| 1 | strict | 0,040 | 8,00 | 6,58 | 8,00 | 4,09 |
| 1 | tie | 0,050 | 8,00 | 6,58 | 8,00 | 4,09 |
| 2 | HBOS | 0,050 | 0,09 | 4,36 | 0,16 | 0,02 |
| 2 | IForest | 0,050 | 0,18 | 4,88 | 0,25 | 0,00 |
| 2 | INNE | 0,050 | 6,63 | 5,84 | 6,91 | 3,40 |
| 2 | OCSVM | 0,050 | 0,00 | 4,96 | 0,00 | 0,00 |
| 2 | or | 0,040 | 0,20 | 4,72 | 0,91 | 0,01 |
| 2 | strict | 0,100 | 0,20 | 4,72 | 0,91 | 0,01 |
| 2 | tie | 0,050 | 0,20 | 4,72 | 0,91 | 0,01 |

### T

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | HBOS | 0,040 | 100,00 | 100,00 | 16,76 | 16,76 |
| 0 | IForest | 0,050 | 48,20 | 14,10 | 32,89 | 6,32 |
| 0 | INNE | 0,040 | 43,88 | 8,80 | 43,33 | 10,66 |
| 0 | OCSVM | 0,050 | 45,23 | 12,62 | 12,38 | 0,11 |
| 0 | or | 0,040 | 47,69 | 13,60 | 20,41 | 7,48 |
| 0 | strict | 0,100 | 47,69 | 13,60 | 20,41 | 7,48 |
| 0 | tie | 0,050 | 47,69 | 13,60 | 20,41 | 7,48 |
| 1 | HBOS | 0,040 | 24,02 | 11,66 | 17,26 | 2,82 |
| 1 | IForest | 0,040 | 21,88 | 8,82 | 11,73 | 0,00 |
| 1 | INNE | 0,040 | 22,95 | 9,12 | 17,62 | 3,72 |
| 1 | OCSVM | 0,040 | 19,34 | 9,18 | 11,41 | 0,00 |
| 1 | or | 0,040 | 21,32 | 8,94 | 11,63 | 0,86 |
| 1 | strict | 0,050 | 21,32 | 8,94 | 11,63 | 0,86 |
| 1 | tie | 0,040 | 21,32 | 8,94 | 11,63 | 0,86 |
| 2 | HBOS | 0,050 | 3,03 | 6,86 | 2,79 | 0,02 |
| 2 | IForest | 0,050 | 2,91 | 6,78 | 2,61 | 0,00 |
| 2 | INNE | 0,040 | 3,27 | 7,14 | 2,68 | 0,00 |
| 2 | OCSVM | 0,050 | 2,77 | 6,78 | 2,62 | 0,00 |
| 2 | or | 0,040 | 3,04 | 6,96 | 2,59 | 0,02 |
| 2 | strict | 0,050 | 3,04 | 6,96 | 2,59 | 0,02 |
| 2 | tie | 0,050 | 3,04 | 6,96 | 2,59 | 0,02 |


## 4. Chẩn đoán zero-pad (AUROC, IForest contamination 0,05)

Chẩn đoán, không phải điểm vận hành: tách AUROC theo số gói tin thực của edge test để kiểm tra liệu edge zero-pad có tạo ra khả năng phân biệt giả.

| protocol | seed | tập con | edge tấn công | edge benign | AUROC |
|---|---:|---|---:|---:|---:|
| P_paper | 0 | all_edges | 25041 | 5000 | 0,4605 |
| P_paper | 0 | full_8_packets | 17018 | 5000 | 0,3474 |
| P_paper | 0 | padded_attacks | 8023 | 5000 | 0,7003 |
| P_paper | 1 | all_edges | 25041 | 5000 | 0,5440 |
| P_paper | 1 | full_8_packets | 17018 | 5000 | 0,4126 |
| P_paper | 1 | padded_attacks | 8023 | 5000 | 0,8229 |
| P_paper | 2 | all_edges | 25041 | 5000 | 0,5509 |
| P_paper | 2 | full_8_packets | 17018 | 5000 | 0,4656 |
| P_paper | 2 | padded_attacks | 8023 | 5000 | 0,7317 |
| T | 0 | all_edges | 25907 | 5000 | 0,7045 |
| T | 0 | full_8_packets | 25907 | 5000 | 0,7045 |
| T | 0 | padded_attacks | 0 | 5000 | n/a |
| T | 1 | all_edges | 25907 | 5000 | 0,5871 |
| T | 1 | full_8_packets | 25907 | 5000 | 0,5871 |
| T | 1 | padded_attacks | 0 | 5000 | n/a |
| T | 2 | all_edges | 25907 | 5000 | 0,5114 |
| T | 2 | full_8_packets | 25907 | 5000 | 0,5114 |
| T | 2 | padded_attacks | 0 | 5000 | n/a |

## 5. Kết luận

`P_paper` đạt 3,25% TPR ở FPR matched 6,56% với luật OR của code tác giả (luật tie: 3,25%; cả ba luật vote cho cùng TPR vì dùng chung score fusion). Detector tốt nhất (IForest) đạt 8,90%. Trên cùng pipeline, protocol `T` sạch (luật tie) đạt 11,54%. So với 99,04% của paper, khoảng cách vẫn hơn 60 điểm phần trăm. Khớp thành phần tập test (Table VII), grid contamination (Table V) và luật OR của code tác giả **không** thu hẹp khoảng cách, nên kết quả âm của bản tái hiện là bền vững theo cách dựng dữ liệu: con số ~99% không tái lập được từ artefact công khai dưới cả hai định nghĩa flow.
