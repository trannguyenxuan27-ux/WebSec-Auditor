"""Reporting package: JSON + HTML outputs."""
from report.html_report import save_html
from report.json_report import save_json

__all__ = ["save_json", "save_html"]
