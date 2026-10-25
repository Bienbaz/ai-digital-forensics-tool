"""Simple desktop GUI: load a CSV, detect anomalies, export a PDF report."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from data_preprocessing import load_logs
from model import detect, load_bundle, train
from report import write_pdf_report

DEFAULT_MODEL = os.path.join(os.path.dirname(__file__), "..", "models", "anomaly_detector.pkl")
COLUMNS = ["timestamp", "user", "src_ip", "event_type", "status", "bytes_transferred", "anomaly_score"]


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AI Digital Forensics Tool")
        self.geometry("1000x520")
        self.path = None
        self.scored = None

        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Upload CSV log", command=self.upload).pack(side="left")
        ttk.Button(bar, text="Detect Anomalies", command=self.run_detection).pack(side="left", padx=6)
        ttk.Button(bar, text="Export PDF report", command=self.export_pdf).pack(side="left")
        self.status = tk.StringVar(value="Upload a CSV log file to begin.")
        ttk.Label(self, textvariable=self.status, padding=8).pack(fill="x")

        self.table = ttk.Treeview(self, columns=COLUMNS, show="headings")
        for col in COLUMNS:
            self.table.heading(col, text=col)
            self.table.column(col, width=130, anchor="w")
        self.table.pack(fill="both", expand=True, padx=8, pady=8)

    def upload(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if path:
            self.path = path
            self.scored = None
            self.status.set(f"Loaded: {os.path.basename(path)}")

    def run_detection(self) -> None:
        if not self.path:
            messagebox.showinfo("No file", "Upload a CSV log file first.")
            return
        try:
            df = load_logs(self.path)
            if os.path.exists(DEFAULT_MODEL):
                bundle = load_bundle(DEFAULT_MODEL)
                note = "using saved model"
            else:
                bundle = train(df)
                note = "no saved model found, trained on this file"
            self.scored = detect(df, bundle)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Error", str(exc))
            return
        flagged = self.scored[self.scored["is_flagged"]].sort_values("anomaly_score", ascending=False)
        self.table.delete(*self.table.get_children())
        for _, row in flagged.iterrows():
            self.table.insert("", "end", values=[str(row[c]) if c != "anomaly_score" else f"{row[c]:.3f}" for c in COLUMNS])
        self.status.set(f"{len(flagged)} of {len(self.scored)} rows flagged ({note}).")

    def export_pdf(self) -> None:
        if self.scored is None:
            messagebox.showinfo("Nothing to export", "Run detection first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if path:
            try:
                write_pdf_report(self.scored, path, source_name=os.path.basename(self.path))
                self.status.set(f"Report saved to {path}")
            except (RuntimeError, OSError) as exc:
                messagebox.showerror("Error", str(exc))


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
