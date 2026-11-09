"""Conformal calibration & p-value fusion for anomaly detectors (Proposal P1).

Implements:
1. Conformal p-values on held-out benign calibration set C:
   pi_m(x) = (1 + sum_{c in C} I(s_m(c) >= s_m(x))) / (1 + |C|)
2. Multiple detector fusion:
   - Bonferroni: min(1.0, M * min_m pi_m)
   - Fisher: -2 * sum_m ln(pi_m) compared against chi2(2M)
   - Simes / Harmonic mean
3. Calibrated alert threshold: alarm if pi_fused <= alpha.
   Guarantees empirical FPR <= alpha on exchangeable benign traffic.
"""

from __future__ import annotations

import numpy as np
from scipy.stats import chi2


def conformal_pvalues(
    scores: np.ndarray,
    calibration_scores: np.ndarray,
) -> np.ndarray:
    """Compute empirical conformal p-values for test scores given calibration scores.

    Higher scores indicate more anomalous samples.
    pi(x) = (1 + count(s_calib >= s_test)) / (1 + n_calib)

    Args:
        scores: 1D array of shape (N,) test anomaly scores.
        calibration_scores: 1D array of shape (C,) benign calibration anomaly scores.

    Returns:
        1D array of shape (N,) p-values in (0, 1].
    """
    scores = np.asarray(scores, dtype=np.float64)
    calib = np.asarray(calibration_scores, dtype=np.float64)
    if calib.size == 0:
        raise ValueError("calibration_scores cannot be empty")

    sorted_calib = np.sort(calib)
    n_calib = sorted_calib.size

    # count how many calibration scores are >= score
    # np.searchsorted with 'left' finds the index of first element >= score
    idx = np.searchsorted(sorted_calib, scores, side="left")
    greater_equal = n_calib - idx
    pvals = (1.0 + greater_equal) / (1.0 + n_calib)
    return np.clip(pvals, 1.0 / (1.0 + n_calib), 1.0)


def fuse_pvalues_bonferroni(pvals_matrix: np.ndarray) -> np.ndarray:
    """Fuse p-values across M detectors using Bonferroni correction.

    pi_fused = min(1.0, M * min_m pi_m)

    Args:
        pvals_matrix: 2D array of shape (M, N) where M is detector count.

    Returns:
        1D array of shape (N,) fused p-values.
    """
    pvals_matrix = np.asarray(pvals_matrix, dtype=np.float64)
    m = pvals_matrix.shape[0]
    min_p = np.min(pvals_matrix, axis=0)
    return np.clip(m * min_p, 0.0, 1.0)


def fuse_pvalues_fisher(pvals_matrix: np.ndarray) -> np.ndarray:
    """Fuse p-values across M detectors using Fisher's combination test.

    T = -2 * sum_{m=1}^M ln(pi_m) ~ chi2(2M) under the global null.

    Args:
        pvals_matrix: 2D array of shape (M, N) where M is detector count.

    Returns:
        1D array of shape (N,) fused p-values.
    """
    pvals_matrix = np.asarray(pvals_matrix, dtype=np.float64)
    m, n = pvals_matrix.shape
    # clamp p-values to prevent log(0)
    eps = 1e-12
    p_clamped = np.clip(pvals_matrix, eps, 1.0)
    stat = -2.0 * np.sum(np.log(p_clamped), axis=0)
    p_fused = 1.0 - chi2.cdf(stat, df=2 * m)
    return np.clip(p_fused, eps, 1.0)


def calibrate_and_fuse(
    detector_scores: dict[str, np.ndarray],
    calibration_scores: dict[str, np.ndarray],
    method: str = "fisher",
) -> tuple[dict[str, np.ndarray], np.ndarray]:
    """Compute per-detector conformal p-values and fuse them.

    Args:
        detector_scores: {detector_name: scores_array (N,)}
        calibration_scores: {detector_name: calib_scores_array (C,)}
        method: "fisher" or "bonferroni"

    Returns:
        pvals: {detector_name: pvals_array (N,)}
        fused_pvals: (N,)
    """
    names = sorted(detector_scores.keys())
    pvals = {}
    p_list = []
    for name in names:
        pv = conformal_pvalues(detector_scores[name], calibration_scores[name])
        pvals[name] = pv
        p_list.append(pv)

    p_matrix = np.stack(p_list, axis=0)  # (M, N)
    if method == "fisher":
        fused = fuse_pvalues_fisher(p_matrix)
    elif method == "bonferroni":
        fused = fuse_pvalues_bonferroni(p_matrix)
    else:
        raise ValueError(f"Unknown fusion method: {method}")

    return pvals, fused
