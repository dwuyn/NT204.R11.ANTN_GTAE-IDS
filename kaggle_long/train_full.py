"""Kaggle full-training kernel: merge split datasets and run all p/seeds.

Uses --resume, so rerunning after a session limit continues where it stopped.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

INPUT = Path("/kaggle/input")
WORK = Path("/kaggle/working")
ROOT = WORK / "gtae"

code_mount = None
graph_roots: list[Path] = []
for root, _dirs, files in os.walk(INPUT):
    root_path = Path(root)
    if code_mount is None and "train_gtae.py" in files and root_path.name == "src":
        code_mount = root_path.parent
    if root_path.name == "T" and root_path.parent.name == "graphs":
        graph_roots.append(root_path)

if code_mount is None:
    raise FileNotFoundError(f"no code mount under {INPUT}")
if not graph_roots:
    raise FileNotFoundError(f"no data/graphs/T mount under {INPUT}")

ROOT.mkdir(parents=True, exist_ok=True)
for name in ("src", "configs", "scripts", "pytest.ini"):
    source = code_mount / name
    target = ROOT / name
    if source.is_dir():
        shutil.copytree(source, target, dirs_exist_ok=True)
    elif source.exists():
        shutil.copy2(source, target)

graph_root = ROOT / "data" / "graphs" / "T"
for source in graph_roots:
    for part in sorted(source.glob("p*")):
        shutil.copytree(part, graph_root / part.name, dirs_exist_ok=True)

print("graph parts:", sorted(p.name for p in graph_root.glob("p*")), flush=True)
available = sorted(
    int(part.name[1:]) for part in graph_root.glob("p*") if part.name.startswith("p")
)
if not available:
    raise FileNotFoundError(f"no graph parts under {graph_root}")

cmd = [
    sys.executable,
    str(ROOT / "scripts" / "train_all.py"),
    "--graphs",
    str(graph_root),
    "--out",
    str(WORK / "experiments" / "T"),
    "--ps",
    *[str(p) for p in available],
    "--seeds",
    "0", "1", "2",
    "--epochs",
    "100",
    "--batch-subgraphs",
    "50",
    "--max-edges",
    "200",
    "--patience",
    "100",
    "--device",
    "auto",
    "--resume",
]
print("=== CMD:", " ".join(cmd), flush=True)
subprocess.run(cmd, check=True)

print("=== runs", flush=True)
run_log = WORK / "experiments" / "T" / "runs.jsonl"
if run_log.exists():
    print(run_log.read_text(), flush=True)
