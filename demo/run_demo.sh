#!/usr/bin/env bash
# Script run demo 5 phút cho buổi báo cáo đồ án GTAE-IDS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=========================================================================="
echo " GTAE-IDS Demo: P1 Calibrated Early-Exit Anomaly Detection (NT204.R11)"
echo "=========================================================================="
echo ""
echo "[*] Kích hoạt môi trường và chạy pipeline mô phỏng..."
PYTHONPATH=. .venv/bin/python demo/run_demo.py --samples 30 --alpha 0.05 --seed 0
