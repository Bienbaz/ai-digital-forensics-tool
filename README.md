# AI-Powered Digital Forensics Tool for Cybercrime Investigation

## Overview

This project is a Python-based toolkit that uses machine learning to automate log analysis and detect suspicious or anomalous behavior in system logs. It is designed to assist digital forensic investigators in identifying potential signs of cybercrime.

## Features

- Loads and preprocesses system/network log data (`data_preprocessing.py`)
- Extracts features suitable for anomaly detection
- Trains an unsupervised ML model (Isolation Forest by default)
- Detects and flags anomalous activities in new log data
- CLI and GUI interface for log upload, model training, anomaly detection, and PDF reporting
- Outputs flagged entries for further forensic analysis

## Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Prepare sample logs

A sample CSV is provided in `data/sample_logs.csv`.

### 3. Train the anomaly detection model

```bash
python src/cli_tool.py --train --input data/sample_logs.csv --model models/anomaly_detector.pkl
```

### 4. Detect anomalies in new logs

```bash
python src/cli_tool.py --detect --input data/sample_logs.csv --model models/anomaly_detector.pkl --output outputs/suspicious_entries.csv
```

### 5. Use the GUI

```bash
python src/gui_tool.py
```
- Upload your CSV log file.
- Click "Detect Anomalies" to view suspicious entries.
- Export the flagged entries as a PDF report.

### 6. View results

Flagged suspicious entries will be saved to `outputs/suspicious_entries.csv` (CLI) or as a PDF (GUI).

## Optional Enhancements

- Integration with Autopsy or ELK Stack
- Exporting analysis report in PDF format

## License

MIT License (c) 2025 Bienbaz