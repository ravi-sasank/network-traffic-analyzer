"""Report download endpoints.

Append these to backend/api/main.py (or import them). They stream the
generated file straight to the browser with a dated filename.
"""
from datetime import datetime, timezone

from fastapi import Response

from backend.storage.db import get_connection
from backend.reports.pdf_report import build_report
from backend.reports.excel_report import build_workbook


def _stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')


def register(app):
    """Attach the report routes to a FastAPI app."""

    @app.get('/api/report/pdf')
    def report_pdf():
        conn = get_connection()
        try:
            data = build_report(conn)
        finally:
            conn.close()
        return Response(
            content=data,
            media_type='application/pdf',
            headers={'Content-Disposition':
                     f'attachment; filename="sentinel-report-{_stamp()}.pdf"'},
        )

    @app.get('/api/report/excel')
    def report_excel():
        conn = get_connection()
        try:
            data = build_workbook(conn)
        finally:
            conn.close()
        return Response(
            content=data,
            media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition':
                     f'attachment; filename="sentinel-report-{_stamp()}.xlsx"'},
        )
