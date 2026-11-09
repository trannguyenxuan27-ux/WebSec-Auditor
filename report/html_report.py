"""HTML report writer — findings grouped by severity."""
from __future__ import annotations

import html
from pathlib import Path

from models import ScanResult

_SEVERITY_COLORS = {
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#1d4ed8",
    "Info": "#475569",
}


def save_html(result: ScanResult, path: str | Path) -> Path:
    out = Path(path)
    summary = result.summary()

    rows_html = []
    for severity in ("High", "Medium", "Low", "Info"):
        items = [f for f in result.findings if f.severity == severity]
        if not items:
            continue
        color = _SEVERITY_COLORS.get(severity, "#333")
        rows_html.append(f"<h2 style='color:{color}'>{severity} ({len(items)})</h2>")
        rows_html.append(
            "<table><tr><th>Scanner</th><th>Endpoint</th><th>Title</th>"
            "<th>Evidence</th><th>Recommendation</th></tr>"
        )
        for f in items:
            rows_html.append(
                "<tr>"
                f"<td>{html.escape(f.scanner)}</td>"
                f"<td>{html.escape(f.endpoint)}</td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td>{html.escape(f.evidence)}</td>"
                f"<td>{html.escape(f.recommendation)}</td>"
                "</tr>"
            )
        rows_html.append("</table>")

    body = "\n".join(rows_html) if rows_html else "<p>No findings. Target looks clean.</p>"

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>WebSec-Auditor Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#1f2937}}
table{{border-collapse:collapse;width:100%;margin-bottom:2rem}}
th,td{{border:1px solid #d1d5db;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}}
.meta{{background:#f9fafb;padding:1rem;border-radius:8px}}
</style></head>
<body>
<h1>WebSec-Auditor Report</h1>
<div class="meta">
<p><b>Target:</b> {html.escape(result.target)}</p>
<p><b>Started:</b> {html.escape(result.start_time)} &nbsp; <b>Finished:</b> {html.escape(result.end_time)}</p>
<p><b>Endpoints scanned:</b> {result.endpoints_scanned} &nbsp; <b>Total findings:</b> {summary.get('total', 0)}</p>
<p><b>By severity:</b> High={summary.get('High', 0)} Medium={summary.get('Medium', 0)} Low={summary.get('Low', 0)} Info={summary.get('Info', 0)}</p>
</div>
{body}
<hr><p><i>Authorised testing only. Do not use this report against systems you do not own.</i></p>
</body></html>
"""
    out.write_text(doc, encoding="utf-8")
    return out
