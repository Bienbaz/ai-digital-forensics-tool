"""Train, save, load and apply the Isolation Forest anomaly detector."""

from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from data_preprocessing import FEATURE_NAMES, build_features


def train(df: pd.DataFrame, contamination: float = 0.02, random_state: int = 42) -> dict:
    """Fit an Isolation Forest on `df` and return a bundle ready to save.

    `contamination` is the share of rows you expect to be anomalous. It only
    sets the flagging threshold; it is not learned from labels.
    """
    features, stats, _ = build_features(df)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(features[FEATURE_NAMES])
    return {
        "model": model,
        "stats": stats,
        "features": FEATURE_NAMES,
        "contamination": contamination,
        "trained_rows": int(len(df)),
    }


def save_bundle(bundle: dict, path: str) -> None:
    joblib.dump(bundle, path)


def load_bundle(path: str) -> dict:
    return joblib.load(path)


def detect(df: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    """Score every row. Adds `anomaly_score` (higher = more unusual) and `is_flagged`."""
    features, _, ordered = build_features(df, bundle["stats"])
    x = features[bundle["features"]]
    out = ordered.copy()
    out["anomaly_score"] = -bundle["model"].score_samples(x)
    out["is_flagged"] = bundle["model"].predict(x) == -1
    return out
