#!/usr/bin/env bash
# Build the submission PDF from reports/report.md.
#
# Needs pandoc + xelatex (Debian: pandoc texlive-xetex texlive-latex-recommended
# texlive-fonts-recommended) and the DejaVu fonts. The pandoc static binary works too:
#   curl -L -o /tmp/pandoc.tar.gz \
#     https://github.com/jgm/pandoc/releases/download/3.1.11/pandoc-3.1.11-linux-amd64.tar.gz
#   tar -xzf /tmp/pandoc.tar.gz -C /tmp
#   PANDOC=/tmp/pandoc-3.1.11/bin/pandoc scripts/build_report_pdf.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANDOC="${PANDOC:-pandoc}"
OUT="${OUT:-$ROOT/reports/GTAE-IDS_NhomB_BaoCao.pdf}"

"$PANDOC" "$ROOT/reports/report.md" \
  -o "$OUT" \
  --pdf-engine=xelatex \
  -V fontsize=10pt \
  -V geometry:margin=1.8cm \
  -V mainfont="DejaVu Sans" \
  -V monofont="Noto Sans Mono" \
  -V monofontoptions="Scale=0.88" \
  -V linestretch=1.06 \
  --toc --toc-depth=2 \
  -V colorlinks=true \
  -V linkcolor=blue \
  -V urlcolor=blue \
  -V lang=vi \
  --metadata title="GTAE-IDS — Báo cáo đồ án" \
  --metadata author="NT204.R11.ANTN"

echo "wrote $OUT"
