import numpy as np
import pytest

from src.calibrate import (
    calibrate_and_fuse,
    conformal_pvalues,
    fuse_pvalues_bonferroni,
    fuse_pvalues_fisher,
)
from src.early_exit import run_early_exit


def test_conformal_pvalues_uniform_under_null():
    # If calibration and test are drawn from same distribution, p-values should be uniform
    rng = np.random.default_rng(42)
    calib = rng.normal(0, 1, size=1000)
    test_benign = rng.normal(0, 1, size=1000)
    
    pvals = conformal_pvalues(test_benign, calib)
    assert pvals.min() > 0.0
    assert pvals.max() <= 1.0
    # FPR at alpha=0.05 should be close to 0.05
    empirical_fpr = (pvals <= 0.05).mean()
    assert 0.03 <= empirical_fpr <= 0.07


def test_conformal_pvalues_detects_shift():
    rng = np.random.default_rng(42)
    calib = rng.normal(0, 1, size=1000)
    test_attack = rng.normal(5, 1, size=200)  # Strong anomaly
    
    pvals = conformal_pvalues(test_attack, calib)
    # Most anomalies should have very small p-values
    assert (pvals < 0.01).mean() > 0.95


def test_fuse_bonferroni():
    # 4 detectors
    pvals = np.array([
        [0.01, 0.50],
        [0.02, 0.80],
        [0.03, 0.40],
        [0.04, 0.90],
    ])
    fused = fuse_pvalues_bonferroni(pvals)
    assert len(fused) == 2
    assert fused[0] == pytest.approx(4 * 0.01)
    assert fused[1] == pytest.approx(min(1.0, 4 * 0.40))


def test_fuse_fisher():
    pvals = np.array([
        [0.01, 0.50],
        [0.01, 0.50],
        [0.01, 0.50],
        [0.01, 0.50],
    ])
    fused = fuse_pvalues_fisher(pvals)
    assert len(fused) == 2
    assert fused[0] < 0.001
    assert fused[1] > 0.1


def test_early_exit_flow():
    rng = np.random.default_rng(0)
    ps = [2, 4, 8]
    n = 100
    y_true = np.array([0] * 50 + [1] * 50)
    
    scores_by_p = {}
    calib_scores_by_p = {}
    for p in ps:
        calib_scores_by_p[p] = {
            "d1": rng.normal(0, 1, size=200),
            "d2": rng.normal(0, 1, size=200),
        }
        # Attacks become obvious at p=4
        attack_mu = 0.0 if p == 2 else 4.0
        scores_by_p[p] = {
            "d1": np.concatenate([rng.normal(0, 1, size=50), rng.normal(attack_mu, 1, size=50)]),
            "d2": np.concatenate([rng.normal(0, 1, size=50), rng.normal(attack_mu, 1, size=50)]),
        }
    
    res = run_early_exit(scores_by_p, calib_scores_by_p, y_true, alpha=0.05, ps=ps)
    assert res.fpr <= 0.10
    assert res.tpr > 0.80
    # Attacks should trigger early at p=4 instead of waiting for p=8
    assert res.mean_p_attack < 6.0
    assert res.mean_p_benign > 7.0
    assert res.early_exit_rate_attack > 0.70


def test_bonferroni_alpha05_calibration_floor():
    """Bonferroni x4 x7 needs n_calib >= 559 to reach alpha=0.05.

    With 400 calibration flows the smallest fused p-value is
    4 * 1/401 = 0.009975 > 0.05/7, so no score can alert. With 800 flows
    the floor drops below the per-step budget and an all-time-high score
    alerts at p=2.
    """
    ps = (2, 3, 4, 5, 6, 7, 8)
    y_true = np.array([1], dtype=np.int8)
    score = {"d1": np.array([1.0]), "d2": np.array([1.0]),
             "d3": np.array([1.0]), "d4": np.array([1.0])}

    def make_calib(n: int) -> dict[int, dict[str, np.ndarray]]:
        return {p: {name: np.zeros(n) for name in score} for p in ps}

    small = run_early_exit(
        {p: score for p in ps}, make_calib(400), y_true,
        alpha=0.05, method="bonferroni", ps=ps,
    )
    large = run_early_exit(
        {p: score for p in ps}, make_calib(800), y_true,
        alpha=0.05, method="bonferroni", ps=ps,
    )

    assert small.p_decision[0] == 8  # floor prevents any alert
    assert large.p_decision[0] == 2  # min fused p = 4/801 < 0.05/7
