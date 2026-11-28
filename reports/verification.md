# Verification report - P4 ablation and full-project audit

**Date:** 2026-11-29
**Scope:** implement P4a (node = IP), apply the pre-registered gate, then re-check every
headline number and claim in the submission against the committed artefacts.

---

## 1. P4a (node = IP) - implemented and measured

**Implementation.** `src/graph_builder.py::build_graph(..., node_key="ip")` and
`python -m src.build_dataset --node-key ip` build graphs whose nodes are IPs instead of
`(IP, port)`. Edge features, splits, training and detectors are unchanged; only the node
identity and therefore the line graph / LapPE change. A regression test
`tests/test_graph_builder.py::test_build_graph_ip_nodes_merge_ports` covers the merge.

**Graphs.** `data/graphs/T_ip/p8` (commands in Appendix A): train1 5,000 edges / 2,232 nodes,
train2 2,000 / 1,189, test 30,907 / 2,437. The `(IP, port)` graph has 24,030 test nodes, so the
merge removes ~90% of the nodes and creates large victim hubs.

**Training.** 3 seeds, 100 epochs, patience 100, CPU; 28 min total (about 4-5x the `T` graph
because hub-heavy line graphs make sampling slower). Checkpoints in `experiments/T_ip`.

**Result** (`results/P4a/M1_summary.csv`, `results/feature_input/P4a_p8/`):

| Metric | P4a (IP nodes) | B2 (port nodes, reference) | Gate |
|---|---:|---:|---|
| AUROC | **0.536** | 0.689 | >= 0.719 required |
| TPR @ test FPR 6.56% | 12.99% | 16.27% | not worse |
| TPR @ test FPR 1% | **0.05%** | 6.40% | >= 8.40% required |
| TPR / FPR at contamination 0.01 | 2.62% / 3.86% | 9.78% / 1.81% | - |

**Gate: FAILED on both primary conditions** (0.153 AUROC and 6.35 pp TPR@1% short). Per the
pre-registered protocol, **P4b (node features) was not implemented**. Interpretation: port
identity carries information; merging ports destroys signal and creates dense hubs, so graph
fragmentation by ephemeral ports is *not* the binding constraint. This is a recorded negative
result, not a silent omission.

---

## 2. Audit checks run

| Check | Command | Result |
|---|---|---|
| Unit/integration tests | `pytest -q` | **133 passed** |
| Artifact audit | `python scripts/audit_artifacts.py` | **428/428 passed** |
| Report-number verifier | `python scripts/verify_report_numbers.py` | **168/168 passed** |
| Bytecode/app imports | `python -m compileall -q src scripts tests` | OK |
| CLI parsing | every `scripts/*.py --help` | OK |
| PDF build | `scripts/build_report_pdf.sh` | 24 pages |

The verifier recomputes each published number from `results/*.csv` / `results/*.json`:
M1/B0/B1/B2/A2/A3/A5, P1 and A+B, T/P_paper matched FPR, per-class Table VII, P_paper counts,
2018/ACI, latency, direction-leak and vote-threshold tables, supervised probes, checkpoint
probe, Engelen composition, wait_p, and F3/F7. Any changed CSV makes it fail.

---

## 3. Errors found and fixed during the audit

1. **Embedding-cache collision (real bug).** `scripts/eval_paper_parity.py::_embed` cached
   embeddings under `{protocol}_p{p}_seed{s}_{feature_input}` without the model directory.
   `T`, `T_egsage` and `T_noPE` therefore shared the same cache entry. B2 and A2 happened to
   compute their own embeddings in a race, but the later P4a parity run loaded an **A2** cache.
   Fix: the key now includes the model directory (`T_egsage_p8_seed0_z`, ...). B2/A2/P4a were
   re-run with `--no-cache`. Effects:
   - B2 matched FPR 16.27% / AUROC 0.689 unchanged (its run had used B2 embeddings).
   - **A2 corrected from 15.53% to 20.34% TPR @ 6.56%** (AUROC 0.682; TPR@test-1% 6.22%).
     The report's §7.1/§7.2 and Ch.8 were updated.
   - P4a matched FPR corrected to 12.99% (own-threshold 2.62% / 3.86% unchanged).
2. **Wait-time statistic mixing.** `cross_dataset.md` reports the median of the five per-day
   medians, while the report paragraph said "median delay" without qualification. Added
   `results/wait_p_pooled.csv` (flow-level pooling) and clarified both texts: pooled benign
   0.033/0.040/0.085/0.102 s and attack 0.000/0.002/0.053/0.056 s for p=2/4/6/8 (p95
   1.00/1.00/1.84/1.86 s); the per-day median variant remains labelled as such.
3. **Stale test count** 132 -> 133 in report, README, AGENTS, REPRO_AUDIT, WORK_PLAN, slides,
   related_work.
4. **Stale supervised numbers** (18.1% @ 6.7%, AUROC 0.92; 99.4% @ 6.1%, AUROC 0.97) replaced
   by the current artefacts: same-day raw 99.9% @ 6.56% (AUROC 0.999, leak); cross-day raw
   3.2-3.8% (AUROC 0.54); cross-day `z` 11.0-23.2% (AUROC 0.64-0.75).
5. **Unqualified "không tái lập được"** corrected to "không tái lập được bằng cài đặt đúng;
   chỉ tái lập được khi tạo lại artifact hướng" in the abstract, Ch.4, Ch.8, slides and
   WORK_PLAN.
6. **Missing caveat for F9**: added that the authors' `.pkl` is not public, so the finding is
   proven by code path + numerical match, not by opening the pickle.
7. **Calibration vs test FPR labels**: `TPR@FPR=1%` from `M1_summary.csv` is at the 1%
   calibration quantile; the report now labels it and gives the matched test-FPR numbers
   (M1 2.8%, B2 6.4%, A2 6.2%). The earlier "3x" claim was corrected to ~2.2x at test FPR 1%.
8. **P4a added** to the report §7.4, Ch.8, Appendix G and `paper_vs_ours.md` with its gate
   result; no P4b claim is made.

---

## 4. Residual limitations (stated, not hidden)

- The authors' feature `.pkl` is not public; F9 is a code-level + numerical reproduction, not a
  direct inspection of their data.
- HBOS under pyod 3.6.7 degenerates on the artificially zeroed columns in the direction
  simulation (TPR 0-2.5% for HBOS); the ensemble conclusion does not depend on HBOS. This is
  recorded in the analysis.
- P4b was not run because P4a failed the pre-registered gate; no node-feature results exist.
- The exact Table VI operating point (99.04% @ 6.56%) is reproducible only with the authors'
  direction artifact (99.22% @ 6.66%); a faithful implementation stays at 3.25-20.34% at
  matched FPR. This is the project's central finding, not a missing experiment.
- Published numbers from other papers (Tables XI-XIII) are transcribed from the paper PDF /
  `docs/GTAE-IDS_Research_docs.md`; they were cross-checked against the primary sources where
  available and are presented with their conditions.

---

## 5. Bottom line

After the fixes above, every number in the submission that can be recomputed from a committed
artefact matches (168/168 checks), the code compiles, all 133 tests pass, the 428-check artifact
audit passes, and the PDF builds. No fabricated data were found; the one real measurement bug
(cache collision) was found, fixed, and the affected A2/P4a numbers were corrected. The P4
question is answered: **merging ports into IP nodes makes the detector worse, so port
fragmentation is not the bottleneck.**
