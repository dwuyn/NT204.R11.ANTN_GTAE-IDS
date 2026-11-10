# Kaggle GPU: A2 no-LapPE ablation

Kernel: `tdwuyn/gtae-ids-no-pe-training`  
Dataset: `tdwuyn/gtae-ids-ablation` (code + T p2/p4/p8 graphs)

```bash
kaggle kernels push -p kaggle/no_pe
kaggle kernels status tdwuyn/gtae-ids-no-pe-training
kaggle kernels output tdwuyn/gtae-ids-no-pe-training -p /tmp/kaggle_no_pe_out
```

The kernel trains p=8 × seed 0,1,2 with `--no-pe` on T graphs and downloads
`experiments/T_noPE/`. Evaluate locally with:

```bash
python -m src.eval --models experiments/T_noPE --graphs data/graphs/T \
  --out results/noPE --ps 8 --seeds 0 1 2 --device cpu
python scripts/make_ablation_report.py
```
