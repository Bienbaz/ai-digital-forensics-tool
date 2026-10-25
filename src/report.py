"""PDF report export for flagged log entries."""

from __future__ import annotations

from datetime import datetime

import pandas as pd

REPORT_COLUMNS = [
    "timestamp",
    "user",
    "src_ip",
    "event_type",
    "status",
    "bytes_transferred",
    "anomaly_score",
]
MAX_ROWS = 200


def write_pdf_report(scored: pd.DataFrame, path: str, source_name: str = "uploaded log") -> None:
    """Write a short PDF listing the flagged entries, most unusual first."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PDF export needs reportlab: pip install reportlab") from exc

    flagged = scored[scored["is_flagged"]].sort_values("anomaly_score", ascending=False)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Log Anomaly Report", styles["Title"]),
        Paragraph(f"Source: {source_name}", styles["Normal"]),
        Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M}", styles["Normal"]),
        Paragraph(f"Rows analysed: {len(scored)} | Rows flagged: {len(flagged)}", styles["Normal"]),
        Spacer(1, 12),
    ]

    table_rows = [REPORT_COLUMNS]
    for _, row in flagged.head(MAX_ROWS).iterrows():
        table_rows.append(
            [
                str(row["timestamp"]),
                row["user"],
                row["src_ip"],
                row["event_type"],
                row["status"],
                f"{row['bytes_transferred']:.0f}",
                f"{row['anomaly_score']:.3f}",
            ]
        )
    table = Table(table_rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
            ]
        )
    )
    story.append(table)
    if len(flagged) > MAX_ROWS:
        story.append(Paragraph(f"Showing the top {MAX_ROWS} of {len(flagged)} flagged rows.", styles["Italic"]))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Flagged entries are statistically unusual, not proven malicious. "
            "They are leads for a human investigator to review.",
            styles["Italic"],
        )
    )
    SimpleDocTemplate(path, pagesize=landscape(A4)).build(story)
