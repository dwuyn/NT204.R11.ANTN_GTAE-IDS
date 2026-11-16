"""Anomaly detectors on GTAE embeddings (design doc §4.7, T13/D2).

Four PyOD detectors are fitted on benign train2 embeddings only. The ensemble
uses the two voting rules from the paper's ambiguity: >=3/4 (strict) and >=2/4
(tie -> anomaly). Scores are anomaly scores (higher = more abnormal).
"""

from __future__ import annotations

from typing import Iterable, Mapping, MutableMapping

import numpy as np
from scipy.stats import rankdata
from sklearn.metrics import average_precision_score, f1_score, precision_score, roc_auc_score

DETECTOR_NAMES = ("IForest", "OCSVM", "HBOS", "INNE")


def build_detectors(
    contamination: float = 0.01, seed: int = 0
) -> dict[str, object]:
    # Lazy imports keep `metrics` usable on machines without PyOD (e.g. a
    # metrics-only Kaggle kernel) and avoid paying the import cost elsewhere.
    from pyod.models.hbos import HBOS
    from pyod.models.iforest import IForest
    from pyod.models.inne import INNE
    from pyod.models.ocsvm import OCSVM

    return {
        "IForest": IForest(
            n_estimators=150, contamination=contamination, n_jobs=1, random_state=seed
        ),
        "OCSVM": OCSVM(kernel="rbf", gamma="auto", contamination=contamination),
        "HBOS": HBOS(n_bins=20, contamination=contamination),
        "INNE": INNE(n_estimators=100, contamination=contamination, random_state=seed),
    }


class MaskedDetector:
    """Runs a detector on a fixed subset of columns.

    ``pyod``'s HBOS bins every column into equal-width histograms; a column whose
    float32 values collapse to fewer than three distinct numbers cannot be binned
    at all (numpy raises) and carries no information either. Fitting such a
    detector on the informative columns and scoring on the same columns keeps the
    detector's definition intact instead of emitting NaNs or a truncated ladder.
    """

    def __init__(self, inner: object, columns: np.ndarray):
        self.inner = inner
        self.columns = columns

    def fit(self, X: np.ndarray) -> "MaskedDetector":
        self.inner.fit(X[:, self.columns])
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        return self.inner.decision_function(X[:, self.columns])

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.inner.predict(X[:, self.columns])

    @property
    def n_bins(self) -> int:
        return self.inner.n_bins

    @n_bins.setter
    def n_bins(self, value: int) -> None:
        self.inner.n_bins = value

    def __getattr__(self, item: str) -> object:  # threshold_, labels_, ...
        return getattr(self.inner, item)


def _informative_columns(X: np.ndarray) -> np.ndarray:
    """Boolean mask of columns with at least three distinct float32 values."""
    return np.array([np.unique(X[:, i]).size >= 3 for i in range(X.shape[1])], dtype=bool)


def _fit_one(
    name: str, model: object, benign: np.ndarray, notes: dict[str, dict] | None
) -> object:
    """Fit one detector, degrading only as far as the data forces.

    A healthy 20-bin fit is tried first and kept untouched, so detectors that bin
    nothing (IForest/OCSVM/INNE) never change and healthy HBOS fits are identical
    to before. When HBOS cannot bin (numpy refuses columns whose float32 values
    are too few or too tightly packed), the fit degrades in a recorded, bounded
    way: cap ``n_bins`` at the sparsest kept column's distinct-value count and walk
    down to pyod's floor of 3; if that still fails, drop the column with the
    fewest distinct values (it carries almost no information) and retry.
    """
    try:
        model.fit(benign)
        return model
    except ValueError as exc:
        if "Too many bins" not in str(exc) or getattr(model, "n_bins", None) is None:
            raise

    distinct = np.array([np.unique(benign[:, i]).size for i in range(benign.shape[1])])
    keep = distinct >= 3
    if not keep.any():
        raise ValueError(f"{name}: every column is degenerate; cannot fit")
    dropped = int((~keep).sum())

    while keep.any():
        columns = np.flatnonzero(keep)
        start = min(int(getattr(model, "n_bins", 20)), int(distinct[columns].min()))
        for bins in range(start, 2, -1):
            candidate = MaskedDetector(model, keep) if not keep.all() else model
            candidate.n_bins = bins
            try:
                candidate.fit(benign)
            except ValueError as exc:
                if "Too many bins" not in str(exc):
                    raise
                continue
            if notes is not None and (dropped or bins != 20):
                notes[name] = {
                    "n_bins": bins,
                    "dropped_columns": dropped,
                    "reason": "embedding columns too sparse/degenerate to bin",
                }
            return candidate
        keep[columns[np.argmin(distinct[columns])]] = False
        dropped += 1
    raise ValueError(f"{name}: cannot fit even after masking and reducing bins")


def fit_detectors(
    detectors: MutableMapping[str, object],
    benign: np.ndarray,
    notes: dict[str, dict] | None = None,
) -> None:
    """Fit every detector on benign embeddings only.

    ``notes`` records any degradation forced by degenerate embedding columns (see
    `MaskedDetector` and the HBOS bin ladder below), so the affected measurement
    stays auditable. Healthy fits are untouched: the mask is all-True and 20 bins
    are kept.
    """
    for name in list(detectors):
        detectors[name] = _fit_one(name, detectors[name], benign, notes)


def predict_detectors(
    detectors: Mapping[str, object], X: np.ndarray
) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    """Return binary predictions (1 = anomaly) and anomaly scores."""
    predictions: dict[str, np.ndarray] = {}
    scores: dict[str, np.ndarray] = {}
    for name, model in detectors.items():
        predictions[name] = (model.predict(X) == 1).astype(np.int8)
        scores[name] = np.asarray(model.decision_function(X), dtype=np.float64)
    return predictions, scores


def vote(predictions: Mapping[str, np.ndarray], rule: str = "tie") -> np.ndarray:
    """Majority vote: strict = >=3/4, tie = >=2/4."""
    if rule not in ("strict", "tie"):
        raise ValueError(f"unknown voting rule: {rule}")
    votes = np.sum(np.stack(list(predictions.values())), axis=0)
    threshold = 3 if rule == "strict" else 2
    return (votes >= threshold).astype(np.int8)


def rank_normalize(scores: Iterable[float]) -> np.ndarray:
    values = np.asarray(list(scores), dtype=np.float64)
    if values.size == 0:
        return values
    ranks = rankdata(values, method="average")
    return (ranks - 0.5) / values.size


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray | None = None,
    calibration_scores: np.ndarray | None = None,
    target_fpr: float = 0.01,
    attack_types: np.ndarray | None = None,
) -> dict:
    y_true = np.asarray(y_true, dtype=np.int8)
    y_pred = np.asarray(y_pred, dtype=np.int8)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    out: dict = {
        "n": int(y_true.size),
        "positives": int((y_true == 1).sum()),
        "negatives": int((y_true == 0).sum()),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "tpr": _rate(tp, tp + fn),
        "fpr": _rate(fp, fp + tn),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }

    if scores is not None and len(np.unique(y_true)) > 1:
        out["auroc"] = float(roc_auc_score(y_true, scores))
        out["pr_auc"] = float(average_precision_score(y_true, scores))
    else:
        out["auroc"] = None
        out["pr_auc"] = None

    if scores is not None and calibration_scores is not None and out["positives"]:
        threshold = float(np.quantile(calibration_scores, 1.0 - target_fpr))
        out["tpr_at_fpr"] = float((scores[y_true == 1] >= threshold).mean())
        out["fpr_at_threshold"] = float((scores[y_true == 0] >= threshold).mean())
        out["threshold"] = threshold
    else:
        out["tpr_at_fpr"] = None
        out["fpr_at_threshold"] = None
        out["threshold"] = None

    if attack_types is not None and out["positives"]:
        per_class: dict[str, dict] = {}
        types = np.asarray(attack_types)
        for attack in sorted({str(t) for t, y in zip(types, y_true) if y == 1}):
            mask = (y_true == 1) & (types == attack)
            n = int(mask.sum())
            per_class[attack] = {
                "n": n,
                "tpr": float((y_pred[mask] == 1).mean()) if n else None,
            }
        out["per_class_tpr"] = per_class
    return out
