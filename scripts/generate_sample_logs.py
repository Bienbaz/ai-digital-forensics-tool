"""Generate a SYNTHETIC log file with injected attack-like events.

The output is fake data made for demonstration and testing. The `is_anomaly`
column marks the injected events so the detector can be evaluated; it is never
used as a model feature.

Usage: python scripts/generate_sample_logs.py [output.csv]
"""

import sys

import numpy as np
import pandas as pd

SEED = 42
N_NORMAL = 2000
USERS = ["amina", "bala", "chidi", "dayo", "emeka", "fatima", "garba", "hauwa", "ibrahim", "jumoke"]
EVENTS = ["login", "file_access", "file_download", "logout", "config_change"]
EVENT_WEIGHTS = [0.25, 0.45, 0.12, 0.15, 0.03]
COLUMNS = ["timestamp", "user", "src_ip", "event_type", "status", "bytes_transferred", "is_anomaly"]


def generate(seed: int = SEED, include_anomalies: bool = True) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    home_ip = {u: f"10.0.{i // 5}.{10 + i}" for i, u in enumerate(USERS)}
    rows = []

    # Normal behaviour: weekday office hours, each user from their usual IP.
    days = pd.date_range("2025-03-03", periods=10, freq="D")
    days = [d for d in days if d.dayofweek < 5]
    for _ in range(N_NORMAL):
        user = rng.choice(USERS)
        day = rng.choice(days)
        ts = day + pd.Timedelta(hours=int(rng.integers(8, 18)), minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))
        event = rng.choice(EVENTS, p=EVENT_WEIGHTS)
        status = "failure" if (event == "login" and rng.random() < 0.04) else "success"
        size = int(rng.lognormal(8, 1)) if event in ("file_access", "file_download") else 0
        rows.append([ts, user, home_ip[user], event, status, size, 0])

    if not include_anomalies:
        df = pd.DataFrame(rows, columns=COLUMNS)
        return df.sort_values("timestamp").reset_index(drop=True)

    # Anomaly 1: brute-force burst at night from an unknown IP.
    start = pd.Timestamp("2025-03-05 03:10:00")
    for k in range(15):
        rows.append([start + pd.Timedelta(seconds=20 * k), "bala", "185.220.101.7", "login", "failure", 0, 1])
    # Anomaly 2: large night-time downloads (possible data exfiltration).
    for k in range(10):
        ts = pd.Timestamp("2025-03-06 02:30:00") + pd.Timedelta(minutes=3 * k)
        rows.append([ts, "emeka", "10.0.1.14", "file_download", "success", int(rng.integers(80_000_000, 200_000_000)), 1])
    # Anomaly 3: off-hours config changes from a new location.
    for k in range(8):
        ts = pd.Timestamp("2025-03-07 23:40:00") + pd.Timedelta(minutes=5 * k)
        rows.append([ts, "hauwa", "102.89.45.201", "config_change", "success", 0, 1])

    df = pd.DataFrame(rows, columns=COLUMNS)
    return df.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.csv"
    frame = generate()
    frame.to_csv(out, index=False)
    print(f"Wrote {len(frame)} rows ({int(frame['is_anomaly'].sum())} injected anomalies) to {out}")
