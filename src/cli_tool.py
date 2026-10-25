"""Command-line interface: train a model on logs, or detect anomalies in new logs."""

from __future__ import annotations

import argparse
import os
import sys

from sklearn.metrics import precision_recall_fscore_support

from data_preprocessing import load_logs
from model import detect, load_bundle, save_bundle, train
from report import write_pdf_report

LABEL_COLUMN = "is_anomaly"  # optional ground truth, used only for evaluation


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Anomaly detection for system/network logs.")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--train", action="store_true", help="train a model on --input")
    mode.add_argument("--detect", action="store_true", help="flag anomalies in --input")
    p.add_argument("--input", required=True, help="CSV log file")
    p.add_argument("--model", required=True, help="path of the model file (.pkl)")
    p.add_argument("--output", help="CSV of flagged entries (detect mode)")
    p.add_argument("--report", help="optional PDF report path (detect mode)")
    p.add_argument("--contamination", type=float, default=0.02, help="expected share of anomalies (default 0.02)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        df = load_logs(args.input)
        if args.train:
            bundle = train(df, contamination=args.contamination)
            os.makedirs(os.path.dirname(args.model) or ".", exist_ok=True)
            save_bundle(bundle, args.model)
            print(f"Trained on {len(df)} rows. Model saved to {args.model}")
            return 0

        bundle = load_bundle(args.model)
        scored = detect(df, bundle)
        flagged = scored[scored["is_flagged"]].sort_values("anomaly_score", ascending=False)
        print(f"Analysed {len(scored)} rows, flagged {len(flagged)}.")

        if args.output:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            flagged.to_csv(args.output, index=False)
            print(f"Flagged entries written to {args.output}")
        if args.report:
            write_pdf_report(scored, args.report, source_name=os.path.basename(args.input))
            print(f"PDF report written to {args.report}")

        if LABEL_COLUMN in scored.columns:
            truth = scored[LABEL_COLUMN].astype(int)
            pred = scored["is_flagged"].astype(int)
            p, r, f, _ = precision_recall_fscore_support(truth, pred, average="binary", zero_division=0)
            print(f"Against the '{LABEL_COLUMN}' column: precision={p:.2f} recall={r:.2f} f1={f:.2f}")
        return 0
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
