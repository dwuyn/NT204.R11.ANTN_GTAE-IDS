from __future__ import annotations

import math

import pytest

from scripts.make_seed_stats import mean_std, summarize


def test_mean_std_uses_sample_std():
    m, s = mean_std([1.0, 2.0, 3.0])
    assert m == pytest.approx(2.0)
    assert s == pytest.approx(1.0)


def test_mean_std_single_value_has_zero_std():
    assert mean_std([0.5]) == (0.5, 0.0)


def test_mean_std_rejects_empty():
    with pytest.raises(ValueError):
        mean_std([])


def test_summarize_groups_by_p_and_reads_tpr_at_fpr_alias():
    rows = [
        {"p": "8", "tpr": "0.1", "fpr": "0.02", "auroc": "0.7", "tpr_at_fpr_1pct": "0.05"},
        {"p": "8", "tpr": "0.3", "fpr": "0.04", "auroc": "0.5", "tpr_at_fpr_1pct": "0.15"},
        {"p": "2", "tpr": "0.2", "fpr": "0.01", "auroc": "0.6", "tpr_at_fpr_1pct": ""},
    ]
    out = summarize(rows, "x")
    assert [r["p"] for r in out] == [2, 8]
    p8 = out[1]
    assert p8["n_seeds"] == 2
    assert p8["tpr_mean"] == pytest.approx(0.2)
    assert p8["tpr_at_fpr_mean"] == pytest.approx(0.1)
    assert p8["auroc_std"] == pytest.approx(math.sqrt(0.02))
    assert "tpr_at_fpr_mean" not in out[0]
