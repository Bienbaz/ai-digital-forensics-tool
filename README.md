# AI-Powered Digital Forensics Tool for Cybercrime Investigation

A Python toolkit that uses unsupervised machine learning (Isolation Forest) to flag unusual entries in system and network logs, so a forensic investigator can look at the most suspicious events first.

> **Scope, stated plainly:** the tool ranks log entries by how statistically unusual they are. It does not prove that an event is malicious, and it does not replace an investigator. Results below come from **synthetic** data, not real incidents.

Capstone project, Professional Diploma in Cybersecurity (IDEAS programme), Baze University.
Author: Abdulrahman Abdulaziz.

## What it does

- Loads and validates CSV logs (`src/data_preprocessing.py`)
- Builds 11 behavioural features per event: time of day (cyclic), weekend, off-hours, failed status, bytes transferred, how rare the source IP / event type / user-IP pair is, and the number of failures and events by the same user in the last 10 minutes
- Trains an Isolation Forest and saves it (`src/model.py`)
- Scores new logs and flags the most unusual entries
- Command-line interface (`src/cli_tool.py`), desktop GUI (`src/gui_tool.py`) and PDF report export (`src/report.py`)

## Install

```bash
git clone https://github.com/<your-username>/ai-digital-forensics-tool.git
cd ai-digital-forensics-tool
pip install -r requirements.txt
```

Python 3.10+ is recommended. The GUI uses `tkinter`, which ships with most Python installs (on Debian/Ubuntu: `sudo apt install python3-tk`).

## Input format

A CSV with these columns:

| column | example |
|---|---|
| `timestamp` | `2025-03-05 03:14:20` |
| `user` | `bala` |
| `src_ip` | `185.220.101.7` |
| `event_type` | `login`, `file_download`, `config_change`, ... |
| `status` | `success` or `failure` |
| `bytes_transferred` | `0` |

An optional `is_anomaly` column (0/1) is used only to report precision and recall; it is never given to the model.

## Usage

```bash
# 1. Generate the synthetic sample data (already included as data/sample_logs.csv)
python scripts/generate_sample_logs.py data/sample_logs.csv

# 2. Train
python src/cli_tool.py --train --input data/sample_logs.csv --model models/anomaly_detector.pkl

# 3. Detect, write flagged rows to CSV and a PDF report
python src/cli_tool.py --detect --input data/sample_logs.csv --model models/anomaly_detector.pkl \
    --output outputs/suspicious_entries.csv --report outputs/report.pdf

# 4. GUI: upload a CSV, click "Detect Anomalies", export PDF
python src/gui_tool.py
```

`--contamination` (default `0.02`) sets the share of rows you expect to be anomalous. It controls how many entries are flagged and is the main setting to tune.

An example output is in [`docs/example_report.pdf`](docs/example_report.pdf).

## Results (synthetic data)

`data/sample_logs.csv` contains 2,000 normal events plus 33 injected attack-like events: a night-time brute-force burst from an unknown IP, large night-time downloads, and off-hours configuration changes from a new location.

The honest test trains on normal-only logs from one random seed and evaluates on a different log with the attacks injected (this is what `tests/test_pipeline.py` runs):

| rows | flagged | injected attacks found | precision | recall | F1 |
|---|---|---|---|---|---|
| 2,033 | 56 | 33 of 33 | 0.59 | 1.00 | 0.74 |

Read this with care: the attacks are deliberately obvious and the data is simulated, so real-world performance will be lower. About 4 in 10 flags were false alarms, which is why the output is a ranked list for review, not a verdict.

## Tests

```bash
pytest -q
```

## Project structure

```
src/
  data_preprocessing.py   load, validate, feature engineering
  model.py                train / save / load / detect
  cli_tool.py             command-line interface
  gui_tool.py             tkinter GUI
  report.py               PDF report
scripts/generate_sample_logs.py   synthetic data generator
data/sample_logs.csv              synthetic sample logs
tests/test_pipeline.py            automated tests
docs/example_report.pdf           example output
```

## Limitations

- Trained and tested on synthetic data only; not validated on real logs
- Unsupervised: it finds what is unusual compared with the training data, so a poor or already-compromised baseline gives poor results
- Features are tied to the six input columns; other log formats need a converter
- The GUI has no automated tests

## Possible next steps

- Test on public real-world log datasets
- Ingest Windows Event Logs or syslog directly
- Integration with Autopsy or the ELK Stack
- Add an explanation of why each entry was flagged

## License

MIT, see [LICENSE](LICENSE).
