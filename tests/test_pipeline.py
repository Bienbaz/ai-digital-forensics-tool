import os
import sys

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from data_preprocessing import FEATURE_NAMES, build_features, load_logs  # noqa: E402
from generate_sample_logs import generate  # noqa: E402
from model import detect, train  # noqa: E402
from report import write_pdf_report  # noqa: E402


def test_missing_column_raises(tmp_path):
    path = tmp_path / "bad.csv"
    pd.DataFrame({"timestamp": ["2025-01-01 10:00:00"], "user": ["a"]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="missing required column"):
        load_logs(str(path))


def test_features_do_not_use_label():
    df = generate()
    features, _, _ = build_features(df)
    assert "is_anomaly" not in features.columns
    assert list(features.columns) == FEATURE_NAMES
    assert not features.isna().any().any()


def test_detects_injected_anomalies_on_unseen_data():
    """Train on normal-only logs (seed 1); test on a different log (seed 2) with attacks injected."""
    bundle = train(generate(seed=1, include_anomalies=False), contamination=0.02)
    scored = detect(generate(seed=2), bundle)
    attacks = scored[scored["is_anomaly"] == 1]
    recall = attacks["is_flagged"].mean()
    precision = scored[scored["is_flagged"]]["is_anomaly"].mean()
    assert recall >= 0.8, f"recall too low: {recall:.2f}"
    assert precision >= 0.5, f"precision too low: {precision:.2f}"


def test_pdf_report_is_written(tmp_path):
    bundle = train(generate(seed=1, include_anomalies=False))
    scored = detect(generate(seed=2), bundle)
    out = tmp_path / "report.pdf"
    write_pdf_report(scored, str(out), source_name="test")
    assert out.stat().st_size > 1000
