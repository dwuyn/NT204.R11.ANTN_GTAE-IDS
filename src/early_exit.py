"""Early-exit sequential anomaly detection across packet budget p (Proposal P1).

Implements:
1. Sequential hypothesis testing over p = 2, 3, ..., p_max.
2. Error budget spending (Bonferroni alpha-spending: alpha_p = alpha / K).
3. Early exit decision:
   - Alert immediately when fused conformal p-value <= alpha_p.
   - Record p_decision and latency savings.
   - If p == p_max and no alert, classify as Benign.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

import numpy as np

from src.calibrate import calibrate_and_fuse


@dataclass
class EarlyExitResult:
    y_true: np.ndarray
    y_pred: np.ndarray
    p_decision: np.ndarray
    fused_pvalues: dict[int, np.ndarray]
    alpha: float
    method: str
    tpr: float
    fpr: float
    mean_p_attack: float
    mean_p_benign: float
    mean_p_total: float
    early_exit_rate_attack: float


def run_early_exit(
    scores_by_p: Mapping[int, dict[str, np.ndarray]],
    calib_scores_by_p: Mapping[int, dict[str, np.ndarray]],
    y_true: np.ndarray,
    alpha: float = 0.05,
    method: str = "fisher",
    ps: Sequence[int] = (2, 3, 4, 5, 6, 7, 8),
) -> EarlyExitResult:
    """Evaluate sequential early-exit detection across packet budget p.

    Args:
        scores_by_p: {p: {detector_name: scores (N,)}}
        calib_scores_by_p: {p: {detector_name: calib_scores (C,)}}
        y_true: Ground truth binary labels (N,)
        alpha: Target false positive rate budget across all steps.
        method: Fusion method ("fisher" or "bonferroni").
        ps: Sequence of packet counts evaluated in temporal order.

    Returns:
        EarlyExitResult dataclass with decisions, metrics, and packet statistics.
    """
    y_true = np.asarray(y_true, dtype=np.int8)
    n = y_true.size
    k_steps = len(ps)
    alpha_p = alpha / k_steps  # Bonferroni alpha spending per step

    y_pred = np.zeros(n, dtype=np.int8)
    p_decision = np.full(n, ps[-1], dtype=np.int32)
    decided = np.zeros(n, dtype=bool)

    fused_pvalues: dict[int, np.ndarray] = {}

    for p in ps:
        scores = scores_by_p[p]
        calib = calib_scores_by_p[p]
        _, fused = calibrate_and_fuse(scores, calib, method=method)
        fused_pvalues[p] = fused

        # For undecided samples, check if alarm triggers
        trigger = (~decided) & (fused <= alpha_p)
        if np.any(trigger):
            y_pred[trigger] = 1
            p_decision[trigger] = p
            decided[trigger] = True

    # Any sample not decided by p_max is classified as Benign (y_pred=0, p_decision=ps[-1])
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    attack_mask = y_true == 1
    benign_mask = y_true == 0

    mean_p_attack = float(np.mean(p_decision[attack_mask])) if np.any(attack_mask) else float(ps[-1])
    mean_p_benign = float(np.mean(p_decision[benign_mask])) if np.any(benign_mask) else float(ps[-1])
    mean_p_total = float(np.mean(p_decision))

    early_attack = float(np.mean(p_decision[attack_mask] < ps[-1])) if np.any(attack_mask) else 0.0

    return EarlyExitResult(
        y_true=y_true,
        y_pred=y_pred,
        p_decision=p_decision,
        fused_pvalues=fused_pvalues,
        alpha=alpha,
        method=method,
        tpr=tpr,
        fpr=fpr,
        mean_p_attack=mean_p_attack,
        mean_p_benign=mean_p_benign,
        mean_p_total=mean_p_total,
        early_exit_rate_attack=early_attack,
    )
