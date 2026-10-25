"""Load log files and turn them into numeric features for anomaly detection.

Expected CSV columns
--------------------
timestamp          any format pandas can parse (e.g. 2025-03-04 09:15:02)
user               account name
src_ip             source IP address
event_type         e.g. login, file_access, file_download, privilege_change
status             "success" or "failure"
bytes_transferred  number of bytes moved by the event (0 if not applicable)

Any other columns (for example an `is_anomaly` ground-truth label used only
for evaluation) are carried through untouched and are NEVER used as features.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

LOG = logging.getLogger(__name__)

REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "src_ip",
    "event_type",
    "status",
    "bytes_transferred",
]

# Working hours used to decide what counts as "off hours".
WORK_START_HOUR = 7
WORK_END_HOUR = 19
BURST_WINDOW = "10min"


def load_logs(path: str) -> pd.DataFrame:
    """Read a CSV log file, validate it, and return it sorted by time."""
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Log file is missing required column(s): {', '.join(missing)}. "
            f"Required: {', '.join(REQUIRED_COLUMNS)}"
        )

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    bad_time = df["timestamp"].isna().sum()
    if bad_time:
        LOG.warning("Dropping %d row(s) with unreadable timestamps", bad_time)
        df = df.dropna(subset=["timestamp"])

    df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce").fillna(0)
    df["status"] = df["status"].astype(str).str.lower().str.strip()
    df["user"] = df["user"].astype(str)
    df["src_ip"] = df["src_ip"].astype(str)
    df["event_type"] = df["event_type"].astype(str).str.lower().str.strip()

    if df.empty:
        raise ValueError("Log file contains no usable rows.")

    return df.sort_values("timestamp").reset_index(drop=True)


def _rolling_per_user(df: pd.DataFrame, column: str, how: str) -> np.ndarray:
    """Rolling sum/count of `column` per user over BURST_WINDOW.

    `df` must already be sorted by timestamp.
    """
    out = np.zeros(len(df))
    positions = np.arange(len(df))
    for _, group in df.assign(_pos=positions).groupby("user"):
        series = group.set_index("timestamp")[column].rolling(BURST_WINDOW)
        values = series.sum() if how == "sum" else series.count()
        out[group["_pos"].to_numpy()] = values.to_numpy()
    return out


def learn_statistics(df: pd.DataFrame) -> dict:
    """Learn how common each IP, event type and user/IP pair is in `df`.

    These are stored with the model so that new logs are judged against the
    behaviour seen during training.
    """
    return {
        "n": int(len(df)),
        "ip_counts": df["src_ip"].value_counts().to_dict(),
        "event_counts": df["event_type"].value_counts().to_dict(),
        "pair_counts": (df["user"] + "|" + df["src_ip"]).value_counts().to_dict(),
    }


def _rarity(values: pd.Series, counts: dict, n: int) -> np.ndarray:
    """-log(frequency); values never seen in training get the maximum rarity."""
    freq = values.map(counts).fillna(0).to_numpy(dtype=float) / n
    freq = np.where(freq == 0, 1.0 / (n + 1), freq)
    return -np.log(freq)


def build_features(df: pd.DataFrame, stats: dict | None = None):
    """Turn a log DataFrame into a numeric feature matrix.

    Returns (features, stats, sorted_df). If `stats` is None it is learned from `df`
    (training); otherwise the supplied training statistics are reused (detection).
    """
    df = df.sort_values("timestamp").reset_index(drop=True)
    if stats is None:
        stats = learn_statistics(df)
    n = stats["n"]

    hour = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60.0
    is_failure = (df["status"] == "failure").astype(float)
    work = df.assign(is_failure=is_failure, one=1.0)

    features = pd.DataFrame(
        {
            "hour_sin": np.sin(2 * np.pi * hour / 24),
            "hour_cos": np.cos(2 * np.pi * hour / 24),
            "is_weekend": (df["timestamp"].dt.dayofweek >= 5).astype(float),
            "is_off_hours": ((df["timestamp"].dt.hour < WORK_START_HOUR) | (df["timestamp"].dt.hour >= WORK_END_HOUR)).astype(float),
            "is_failure": is_failure,
            "log_bytes": np.log1p(df["bytes_transferred"].clip(lower=0)),
            "ip_rarity": _rarity(df["src_ip"], stats["ip_counts"], n),
            "event_rarity": _rarity(df["event_type"], stats["event_counts"], n),
            "user_ip_rarity": _rarity(df["user"] + "|" + df["src_ip"], stats["pair_counts"], n),
            "failures_10min": _rolling_per_user(work, "is_failure", "sum"),
            "events_10min": _rolling_per_user(work, "one", "count"),
        }
    )
    return features, stats, df


FEATURE_NAMES = [
    "hour_sin",
    "hour_cos",
    "is_weekend",
    "is_off_hours",
    "is_failure",
    "log_bytes",
    "ip_rarity",
    "event_rarity",
    "user_ip_rarity",
    "failures_10min",
    "events_10min",
]
