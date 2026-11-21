"""Pin training and detector hyperparameters to paper Table IV/V."""

from __future__ import annotations

import inspect

from src.detectors import build_detectors
from src.train_gtae import train


def _inner(model):
    return getattr(model, "inner", model)


def test_detector_grid_matches_table_v():
    detectors = build_detectors(contamination=0.01, seed=0)
    assert set(detectors) == {"IForest", "OCSVM", "HBOS", "INNE"}
    iforest = _inner(detectors["IForest"])
    ocsvm = _inner(detectors["OCSVM"])
    hbos = _inner(detectors["HBOS"])
    inne = _inner(detectors["INNE"])
    assert iforest.n_estimators == 150
    assert ocsvm.kernel == "rbf"
    assert hbos.n_bins == 20
    assert inne.n_estimators == 100
    for model in (iforest, ocsvm, hbos, inne):
        assert float(model.contamination) == 0.01


def test_training_defaults_match_table_iv():
    params = inspect.signature(train).parameters
    assert params["epochs"].default == 100
    assert params["lr"].default == 1e-3
    assert params["batch_subgraphs"].default == 50
    assert params["max_edges"].default == 200
