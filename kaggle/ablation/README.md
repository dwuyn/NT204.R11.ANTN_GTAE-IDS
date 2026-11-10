# Kaggle GPU: A3 reconstruction-error ablation

Kernel: `tdwuyn/gtae-ids-ablation-recon`  
Dataset: `tdwuyn/gtae-ids-ablation` (private; code + T p2/p4/p8 graphs + checkpoints + M1/B0/B1 CSVs)

## Rebuild dataset

```bash
# from repo root
rm -rf kaggle_stage/ablation_dataset && mkdir -p kaggle_stage/ablation_dataset
tar -czf kaggle_stage/ablation_dataset/ablation_artifacts.tar.gz -C . \
  src scripts configs pytest.ini requirements.txt \
  data/graphs/T/p2 data/graphs/T/p4 data/graphs/T/p8 \
  experiments/T/p2 experiments/T/p4 experiments/T/p8 \
  results/M1_summary.csv results/B0_summary.csv results/B1_summary.csv
cat > kaggle_stage/ablation_dataset/dataset-metadata.json <<'JSON'
{"title":"GTAE-IDS ablation artifacts","id":"tdwuyn/gtae-ids-ablation","licenses":[{"name":"CC0-1.0"}]}
JSON
kaggle datasets create -p kaggle_stage/ablation_dataset   # or version -m "..."
```

## Push kernel

```bash
kaggle kernels push -p kaggle/ablation
kaggle kernels status tdwuyn/gtae-ids-ablation-recon
kaggle kernels output tdwuyn/gtae-ids-ablation-recon -p /tmp/kaggle_ablation_out
```

The kernel runs p=2,4,8 × seed 0,1,2 on `--device auto` (T4 when available) and writes
`results/A3_recon.csv`, per-run JSON, `results/ablation.csv`, and `reports/ablation.md`.
