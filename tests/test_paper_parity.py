"""Tests for the paper-parity selection logic (per-p grouping)."""

from __future__ import annotations

from scripts.eval_paper_parity import select_rows


def _row(p, seed, rule, contamination, calib_fpr, tpr=50.0):
    return {
        "protocol": "P_paper",
        "p": p,
        "seed": seed,
        "detector_or_rule": rule,
        "contamination": contamination,
        "calib_fpr": calib_fpr,
        "tpr_at_test_fpr_6.56pct": tpr,
    }


def test_selection_is_per_p_and_picks_closest_calibration():
    rows = []
    # the contamination whose calibration FPR is closest to 6.56% differs by p:
    # p=2 -> 0.06 (cont 0.01), p=8 -> 0.065 (cont 0.1)
    for p, fprs in ((2, (0.02, 0.06, 0.50)), (8, (0.20, 0.30, 0.065))):
        for cont, fpr in zip((0.001, 0.01, 0.1), fprs):
            rows.append(_row(p, 0, "tie", cont, fpr))

    picks = select_rows(rows)
    assert len(picks) == 2, "one pick per (p, seed, rule)"
    by_p = {pick["p"]: pick for pick in picks}
    assert set(by_p) == {2, 8}
    assert by_p[2]["contamination"] == 0.01
    assert by_p[8]["contamination"] == 0.1
    assert all("calib_fpr_gap" in pick for pick in picks)


def test_selection_marks_approximate_when_gap_is_large():
    rows = [_row(8, 0, "or", 0.1, 0.5)]
    pick = select_rows(rows)[0]
    assert pick["approximate"] == 1
