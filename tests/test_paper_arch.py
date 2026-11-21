"""Pin the GTAE architecture to paper Table III/IV (reproduction guard)."""

from __future__ import annotations

from src.model_gtae import ARCH, GTAE

# Paper Table III: (encoder layers, heads, bottleneck d, decoder hidden widths).
PAPER_TABLE_III: dict[int, tuple[int, int, int, tuple[int, ...]]] = {
    2: (3, 3, 8, (32, 64)),
    3: (3, 3, 8, (32, 64)),
    4: (4, 4, 16, (32, 64, 128)),
    5: (5, 6, 32, (32, 64, 128)),
    6: (5, 6, 32, (32, 64, 128)),
    7: (6, 8, 64, (32, 64, 128, 256)),
    8: (6, 8, 64, (32, 64, 128, 256)),
}


def test_arch_matches_paper_table_iii():
    assert set(ARCH) == set(PAPER_TABLE_III)
    for p, (layers, heads, d, decoder) in PAPER_TABLE_III.items():
        cfg = ARCH[p]
        assert cfg["layers"] == layers, p
        assert cfg["heads"] == heads, p
        assert cfg["d"] == d, p
        assert tuple(cfg["decoder"]) == decoder, p


def test_input_and_decoder_dimensions_follow_p():
    for p in PAPER_TABLE_III:
        model = GTAE(p)
        in_dim = 50 * p
        assert model.input_proj.in_features == in_dim
        assert model.decoder[-1].out_features == in_dim


def test_dropout_matches_table_iv():
    """Table IV: FFN dropout 0.05 on every layer, attention dropout 0.1 on the last only."""
    model = GTAE(8)
    last = len(model.layers) - 1
    assert model.input_dropout.p == 0.05
    for index, layer in enumerate(model.layers):
        assert layer.ffn[2].p == 0.05
        expected = 0.1 if index == last else 0.0
        assert layer.attn_dropout.p == expected, index
