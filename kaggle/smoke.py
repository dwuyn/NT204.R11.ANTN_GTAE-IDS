"""Kaggle smoke kernel: extract artifacts and train one GTAE run.

Dataset: tdwuyn/gtae-ids-artifacts (contains artifacts.tar.gz).
"""

import os
import subprocess
import sys
import tarfile
from pathlib import Path

INPUT = Path("/kaggle/input")
WORK = Path("/kaggle/working")
mounted = (
    [path for path in INPUT.iterdir() if (path / "data" / "graphs").is_dir()]
    if INPUT.exists()
    else []
)
if mounted:
    ROOT = str(mounted[0])
else:
    # Fallback: the dataset was uploaded as an archive.
    DATASET = INPUT / "gtae-ids-smoke-artifacts"
    ROOT = str(WORK / "gtae")
    os.makedirs(ROOT, exist_ok=True)
    candidates = [
        DATASET / "artifacts_smoke.tar.gz",
        DATASET / "artifacts.tar.gz",
        DATASET / "artifacts.bin",
    ]
    archive = next((path for path in candidates if path.exists()), None)
    if archive is None:
        print("input listing:", [p.name for p in INPUT.iterdir()] if INPUT.exists() else [], flush=True)
        raise FileNotFoundError(f"no dataset archive under {DATASET}")
    with tarfile.open(archive, "r:*") as handle:
        handle.extractall(ROOT)

print("=== environment", flush=True)
subprocess.run(
    [
        sys.executable,
        "-c",
        "import torch, scipy, pyarrow, yaml; "
        "print('torch', torch.__version__, 'cuda', torch.cuda.is_available()); "
        "print('scipy', scipy.__version__, 'pyarrow', pyarrow.__version__)",
    ],
    check=True,
)

cmd = [
    sys.executable,
    os.path.join(ROOT, "scripts", "train_all.py"),
    "--graphs",
    os.path.join(ROOT, "data", "graphs", "T"),
    "--out",
    os.path.join(WORK, "experiments", "smoke"),
    "--ps",
    "8",
    "--seeds",
    "0",
    "--epochs",
    "10",
    "--batch-subgraphs",
    "50",
    "--max-edges",
    "200",
    "--patience",
    "3",
    "--device",
    "auto",
]
print("=== train:", " ".join(cmd), flush=True)
subprocess.run(cmd, check=True)

print("=== outputs", flush=True)
for root, _, files in os.walk(os.path.join(WORK, "experiments")):
    for name in files:
        path = os.path.join(root, name)
        print(path, os.path.getsize(path), flush=True)
