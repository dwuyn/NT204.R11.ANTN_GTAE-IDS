"""Tests for detector ensemble and metrics (synthetic embeddings)."""

from __future__ import annotations

import numpy as np

from src.detectors import (
    build_detectors,
    fit_detectors,
    metrics,
    predict_detectors,
    rank_normalize,
    vote,
)


def _data(seed=0):
    rng = np.random.default_rng(seed)
    train = rng.normal(0, 1, (300, 8))
    benign = rng.normal(0, 1, (80, 8))
    attack = rng.normal(6, 1, (40, 8))
    X = np.vstack([benign, attack])
    y = np.concatenate([np.zeros(80, np.int8), np.ones(40, np.int8)])
    types = np.array(["BENIGN"] * 80 + ["PortScan"] * 40)
    return train, X, y, types


def test_detectors_separate_far_outliers():
    train, X, y, types = _data()
    detectors = build_detectors(contamination=0.01, seed=0)
    fit_detectors(detectors, train)
    preds, scores = predict_detectors(detectors, X)

    for name in ("IForest", "OCSVM", "HBOS", "INNE"):
        result = metrics(y, preds[name], scores[name])
        assert result["tpr"] is not None and result["tpr"] >= 0.9, name
        assert result["fpr"] is not None and result["fpr"] <= 0.1, name

    strict = vote(preds, "strict")
    tie = vote(preds, "tie")
    assert metrics(y, tie, attack_types=types)["tpr"] >= metrics(y, strict)["tpr"]
    assert "PortScan" in metrics(y, tie, attack_types=types)["per_class_tpr"]


def test_rank_normalize_bounds():
    scores = np.array([3.0, 1.0, 2.0])
    ranks = rank_normalize(scores)
    assert ranks.min() > 0 and ranks.max() < 1
    assert np.all(np.diff(ranks[np.argsort(scores)]) > 0)


def test_vote_rules():
    preds = {
        "a": np.array([1, 1, 0, 0], np.int8),
        "b": np.array([1, 1, 0, 0], np.int8),
        "c": np.array([0, 1, 1, 0], np.int8),
        "d": np.array([0, 0, 1, 1], np.int8),
    }
    assert vote(preds, "strict").tolist() == [0, 1, 0, 0]
    assert vote(preds, "tie").tolist() == [1, 1, 1, 0]
