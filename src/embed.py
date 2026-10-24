"""Embed edges with a trained GTAE encoder (design doc §4.7, T13/D1)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from src.graph_builder import GraphArrays, load_graph
from src.line_graph import build_line_graph
from src.model_gtae import GTAE
from src.pe import PE_DIM, edge_pe, laplacian_pe


def load_model(
    checkpoint_path: str | Path, device: torch.device
) -> tuple[GTAE, dict]:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model = GTAE(checkpoint["p"], pe_dim=checkpoint.get("pe_dim", PE_DIM))
    model.load_state_dict(checkpoint["state_dict"])
    model.to(device).eval()
    return model, checkpoint


@torch.no_grad()
def embed_graph(
    model: GTAE,
    graph: GraphArrays,
    device: torch.device,
    k_max: int = 32,
    use_pe: bool = True,
    seed: int = 0,
) -> np.ndarray:
    """Return encoder embeddings ``[E, d]`` for all edges of ``graph``."""
    line = build_line_graph(
        graph.edge_index, graph.num_nodes, max_neighbors=k_max, seed=seed
    )
    x = torch.from_numpy(graph.edge_attr).to(device)
    line_t = torch.as_tensor(line, dtype=torch.long, device=device)

    pe_t = None
    if use_pe:
        node_pe = laplacian_pe(graph.edge_index, graph.num_nodes, k=PE_DIM)
        pe = edge_pe(node_pe, graph.edge_index)
        pe_t = torch.from_numpy(pe).to(device)

    z = model.encode(x, line_t, pe_t)
    return z.cpu().numpy()


def save_embeddings(
    path: str | Path,
    embeddings: np.ndarray,
    graph: GraphArrays,
    p: int,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        z=embeddings.astype(np.float32),
        flow_id=graph.flow_id,
        day=graph.day,
        y=graph.y,
        attack_type=graph.attack_type,
        p=np.int64(p),
    )


def load_embeddings(path: str | Path) -> dict[str, np.ndarray]:
    with np.load(path, allow_pickle=False) as data:
        return {key: data[key] for key in data.files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--graph", required=True, help="graph npz (train2 or test)")
    parser.add_argument("--out", required=True, help="output embedding npz")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument("--k-max", type=int, default=32)
    parser.add_argument("--no-pe", action="store_true")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available() else
        "cpu" if args.device == "auto" else args.device
    )
    model, checkpoint = load_model(args.model, device)
    graph = load_graph(args.graph)
    use_pe = checkpoint.get("use_pe", True) and not args.no_pe
    embeddings = embed_graph(
        model, graph, device, k_max=args.k_max, use_pe=use_pe, seed=args.seed
    )
    save_embeddings(args.out, embeddings, graph, graph.p)
    summary = {
        "model": args.model,
        "graph": args.graph,
        "out": args.out,
        "edges": int(embeddings.shape[0]),
        "dim": int(embeddings.shape[1]),
        "device": str(device),
        "use_pe": use_pe,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
