"""SENTINEL Excel workbook — a designed deliverable, not a CSV dump.

A dark branded summary sheet, embedded charts, data-bar conditional
formatting, severity colouring, frozen headers and auto-filters. Built
with openpyxl only.
"""
import io
import json
from datetime import datetime, timezone

from openpyxl import Workbook
from openpyxl.chart import BarChart, DoughnutChart, LineChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.formatting.rule import CellIsRule, ColorScaleRule, DataBarRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from backend.storage.db import get_connection
from backend.storage import api_queries as aq

# ── palette (matches the console and the PDF) ─────────────────────────────
VOID   = '04070F'
PANEL  = '0B1220'
ICE    = '5AD8EA'
ICEDIM = '2A8FA8'
INK    = '0F1722'
MUTED  = '66788F'
FAINT  = 'DFE7EF'
BAND   = 'F4F8FB'
SEVC = {'critical': 'E8304F', 'high': 'F07C26',
        'medium': 'D9A316', 'low': '2E93B0'}
TIERC = {**SEVC, 'elevated': 'D9A316', 'guarded': '2E93B0', 'normal': '3AA37A'}

THIN = Side(style='thin', color=FAINT)
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
HEAD_FILL = PatternFill('solid', fgColor='14202F')
HEAD_FONT = Font(color='FFFFFF', bold=True, size=9, name='Calibri')
BAND_FILL = PatternFill('solid', fgColor=BAND)


def fmt_bytes(n):
    n = float(n or 0)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{int(n)} {u}" if u == 'B' else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def ts_str(v):
    if not v:
        return ''
    return datetime.fromtimestamp(float(v), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def style_sheet(ws, widths, n_rows, wrap_last=False, freeze='A2', header_row=1):
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for c in ws[header_row]:
        c.fill = HEAD_FILL
        c.font = HEAD_FONT
        c.alignment = Alignment(vertical='center', horizontal='left', indent=1)
        c.border = BORDER
    ws.row_dimensions[header_row].height = 24
    ws.freeze_panes = freeze
    if n_rows:
        ws.auto_filter.ref = (f"A{header_row}:"
                              f"{get_column_letter(len(widths))}{header_row + n_rows}")
    for r in range(header_row + 1, header_row + n_rows + 1):
        ws.row_dimensions[r].height = 17
        for c in range(1, len(widths) + 1):
            cell = ws.cell(row=r, column=c)
            cell.border = BORDER
            cell.font = Font(size=9, name='Calibri')
            cell.alignment = Alignment(
                vertical='center', indent=1,
                wrap_text=(wrap_last and c == len(widths)))
            if r % 2 == 0:
                cell.fill = BAND_FILL
    ws.sheet_view.showGridLines = False


def build_workbook(conn=None):
    own = conn is None
    if own:
        conn = get_connection()
    try:
        stats     = aq.get_stats(conn)
        alerts    = aq.get_alerts(conn, limit=3000)
        board     = aq.get_threat_board(conn)
        talkers   = aq.get_top_talkers(conn, limit=200)
        protocols = aq.get_protocol_breakdown(conn)
        domains   = aq.get_top_domains(conn, limit=30)
        timeline  = aq.get_traffic_timeline(conn, minutes=60)
        span = conn.execute("SELECT MIN(bucket_ts) a, MAX(bucket_ts) b FROM flows").fetchone()
    finally:
        if own:
            conn.close()

    sev_count = {}
    for a in alerts:
        sev_count[a['severity']] = sev_count.get(a['severity'], 0) + 1
    hostile = [b for b in board if b['tier'] in ('critical', 'high')]
    top = board[0]['score'] if board else 0
    posture = ('CRITICAL' if top >= 80 else 'HIGH' if top >= 55
               else 'ELEVATED' if top >= 30 else 'NOMINAL')
    pkey = posture.lower()

    wb = Workbook()

    # ══ OVERVIEW — dark branded landing sheet ════════════════════════════
    ws = wb.active
    ws.title = 'Overview'
    ws.sheet_view.showGridLines = False
    for col, w in zip('ABCDEFGHIJ', (3, 22, 18, 3, 22, 18, 3, 22, 18, 3)):
        ws.column_dimensions[col].width = w
    # dark canvas
    dark = PatternFill('solid', fgColor=VOID)
    for r in range(1, 34):
        for c in range(1, 11):
            ws.cell(row=r, column=c).fill = dark

    ws.merge_cells('B2:I3')
    t = ws['B2']
    t.value = 'S E N T I N E L'
    t.font = Font(size=30, bold=True, color='FFFFFF', name='Calibri')
    t.alignment = Alignment(horizontal='center', vertical='center')
    ws.row_dimensions[2].height = 34

    ws.merge_cells('B4:I4')
    s = ws['B4']
    s.value = 'NETWORK SITUATIONAL AWARENESS  ·  SECURITY ANALYSIS EXPORT'
    s.font = Font(size=9, bold=True, color=ICEDIM, name='Calibri')
    s.alignment = Alignment(horizontal='center')

    ws.merge_cells('B6:I6')
    w6 = ws['B6']
    w6.value = f"Capture window   {ts_str(span['a'])}   —   {ts_str(span['b'])} UTC"
    w6.font = Font(size=10, color='7E93AB', name='Calibri')
    w6.alignment = Alignment(horizontal='center')

    # posture badge
    ws.merge_cells('D8:G9')
    p = ws['D8']
    p.value = f"NETWORK POSTURE   ·   {posture}"
    p.font = Font(size=15, bold=True, color=TIERC.get(pkey, '3AA37A'), name='Calibri')
    p.alignment = Alignment(horizontal='center', vertical='center')
    badge = PatternFill('solid', fgColor=PANEL)
    for r in (8, 9):
        for c in range(4, 8):
            ws.cell(row=r, column=c).fill = badge
    ws.row_dimensions[8].height = 20
    ws.row_dimensions[9].height = 14

    # KPI tiles
    tiles = [
        ('TRAFFIC VOLUME', fmt_bytes(stats['bytes_last_hour'])),
        ('ACTIVE HOSTS', f"{stats['active_devices']:,}"),
        ('FLOWS RECORDED', f"{stats['flows_last_hour']:,}"),
        ('PACKETS OBSERVED', f"{stats['packets_last_hour']:,}"),
        ('DETECTIONS', f"{stats['alerts_last_hour']:,}"),
        ('HOSTS AT RISK', f"{len(hostile):,}"),
        ('PEAK THREAT SCORE', f"{top:.0f} / 100"),
        ('RULES ARMED', '5'),
    ]
    tile_fill = PatternFill('solid', fgColor=PANEL)
    row = 12
    for i, (label, value) in enumerate(tiles):
        col = 2 + (i % 3) * 3
        r = row + (i // 3) * 3
        for cc in (col, col + 1):
            ws.cell(row=r, column=cc).fill = tile_fill
            ws.cell(row=r + 1, column=cc).fill = tile_fill
        lc = ws.cell(row=r, column=col)
        lc.value = label
        lc.font = Font(size=7.5, bold=True, color=MUTED, name='Calibri')
        lc.alignment = Alignment(indent=1, vertical='center')
        vc = ws.cell(row=r + 1, column=col)
        vc.value = value
        vc.font = Font(size=14, bold=True, color='FFFFFF', name='Calibri')
        vc.alignment = Alignment(indent=1, vertical='center')
        ws.row_dimensions[r].height = 14
        ws.row_dimensions[r + 1].height = 20

    ws.merge_cells('B31:I31')
    f = ws['B31']
    f.value = (datetime.now(timezone.utc).strftime('Generated %d %B %Y at %H:%M UTC')
               + '   ·   Captured on operator-administered networks, no offensive testing performed')
    f.font = Font(size=8, color='44586E', name='Calibri')
    f.alignment = Alignment(horizontal='center')

    # ══ DETECTIONS ═══════════════════════════════════════════════════════
    ws = wb.create_sheet('Detections')
    ws.append(['TIMESTAMP (UTC)', 'RULE', 'SEVERITY', 'SOURCE', 'DESTINATION',
               'EVIDENCE', 'RATIONALE'])
    for a in alerts:
        ev = a.get('evidence') or {}
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except ValueError:
                ev = {}
        ws.append([ts_str(a['ts']), a['rule_name'].replace('_', ' '),
                   a['severity'].upper(), a.get('src_ip') or '',
                   a.get('dst_ip') or '',
                   '; '.join(f"{k}={v}" for k, v in ev.items()),
                   a['reason']])
    style_sheet(ws, [19, 20, 12, 26, 26, 42, 86], len(alerts), wrap_last=True)
    for r in range(2, len(alerts) + 2):
        cell = ws.cell(row=r, column=3)
        col = SEVC.get(str(cell.value or '').lower(), MUTED)
        cell.font = Font(size=9, bold=True, color=col, name='Calibri')
        ws.cell(row=r, column=1).font = Font(size=9, name='Consolas')
        ws.cell(row=r, column=4).font = Font(size=9, name='Consolas')

    # ══ RISK BOARD ═══════════════════════════════════════════════════════
    ws = wb.create_sheet('Risk Board')
    ws.append(['HOST', 'SCORE', 'TIER', 'EVENTS', 'MOST RECENT DETECTION'])
    for b in board:
        recent = b['recent'][-1]['rule'].replace('_', ' ') if b.get('recent') else ''
        ws.append([b['host'], round(b['score'], 1), b['tier'].upper(),
                   b['alert_count'], recent])
    style_sheet(ws, [32, 12, 14, 12, 32], len(board))
    for r in range(2, len(board) + 2):
        ws.cell(row=r, column=1).font = Font(size=9, name='Consolas')
        cell = ws.cell(row=r, column=3)
        col = TIERC.get(str(cell.value or '').lower(), MUTED)
        cell.font = Font(size=9, bold=True, color=col, name='Calibri')
    if board:
        rng = f"B2:B{len(board) + 1}"
        ws.conditional_formatting.add(rng, DataBarRule(
            start_type='num', start_value=0, end_type='num', end_value=100,
            color=ICEDIM, showValue=True))
        ws.conditional_formatting.add(rng, CellIsRule(
            operator='greaterThanOrEqual', formula=['80'],
            font=Font(bold=True, color=SEVC['critical'], size=9)))

    # ══ HOST TRAFFIC ═════════════════════════════════════════════════════
    ws = wb.create_sheet('Host Traffic')
    ws.append(['HOST', 'FLOWS', 'PEERS', 'BYTES', 'VOLUME', 'SHARE %'])
    tot_b = sum(t['bytes'] or 0 for t in talkers) or 1
    for t in talkers:
        ws.append([t['src_ip'], t['flows'], t['peers'], t['bytes'],
                   fmt_bytes(t['bytes']),
                   round((t['bytes'] or 0) / tot_b * 100, 2)])
    style_sheet(ws, [32, 12, 12, 16, 14, 12], len(talkers))
    for r in range(2, len(talkers) + 2):
        ws.cell(row=r, column=1).font = Font(size=9, name='Consolas')
        ws.cell(row=r, column=4).number_format = '#,##0'
    if talkers:
        ws.conditional_formatting.add(
            f"F2:F{len(talkers) + 1}",
            DataBarRule(start_type='num', start_value=0, end_type='max',
                        color=ICEDIM, showValue=True))

    # ══ PROTOCOLS + chart ════════════════════════════════════════════════
    ws = wb.create_sheet('Protocols')
    ws.append(['PROTOCOL', 'FLOWS', 'BYTES', 'SHARE %'])
    tot_p = sum(p['bytes'] or 0 for p in protocols) or 1
    for p in protocols:
        ws.append([p['protocol'], p['flows'], p['bytes'],
                   round((p['bytes'] or 0) / tot_p * 100, 2)])
    style_sheet(ws, [18, 14, 18, 14], len(protocols))
    for r in range(2, len(protocols) + 2):
        ws.cell(row=r, column=3).number_format = '#,##0'
    if protocols:
        ch = DoughnutChart(holeSize=55)
        ch.title = 'Traffic share by protocol'
        ch.height, ch.width = 8.4, 13.5
        ch.add_data(Reference(ws, min_col=3, min_row=1, max_row=len(protocols) + 1),
                    titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=len(protocols) + 1))
        ch.dataLabels = DataLabelList()
        ch.dataLabels.showPercent = True
        ws.add_chart(ch, 'F2')

    # ══ SEVERITY + chart ═════════════════════════════════════════════════
    ws = wb.create_sheet('Severity')
    ws.append(['SEVERITY', 'COUNT'])
    order = [s for s in ('critical', 'high', 'medium', 'low') if sev_count.get(s)]
    for s in order:
        ws.append([s.upper(), sev_count[s]])
    style_sheet(ws, [18, 14], len(order))
    for r in range(2, len(order) + 2):
        cell = ws.cell(row=r, column=1)
        cell.font = Font(size=9, bold=True,
                         color=SEVC.get(str(cell.value or '').lower(), MUTED),
                         name='Calibri')
    if order:
        ch = BarChart()
        ch.type = 'bar'
        ch.title = 'Detections by severity'
        ch.height, ch.width = 7.2, 13
        ch.add_data(Reference(ws, min_col=2, min_row=1, max_row=len(order) + 1),
                    titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=len(order) + 1))
        ch.dataLabels = DataLabelList()
        ch.dataLabels.showVal = True
        ws.add_chart(ch, 'D2')

    # ══ THROUGHPUT + chart ═══════════════════════════════════════════════
    ws = wb.create_sheet('Throughput')
    ws.append(['MINUTE (UTC)', 'BYTES', 'PACKETS'])
    for t in timeline:
        ws.append([ts_str(t['minute']), t['bytes'], t.get('packets', 0)])
    style_sheet(ws, [20, 16, 14], len(timeline))
    for r in range(2, len(timeline) + 2):
        ws.cell(row=r, column=2).number_format = '#,##0'
    if len(timeline) > 1:
        ch = LineChart()
        ch.title = 'Throughput over the capture window'
        ch.height, ch.width = 8, 20
        ch.y_axis.title = 'Bytes per minute'
        ch.add_data(Reference(ws, min_col=2, min_row=1, max_row=len(timeline) + 1),
                    titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=len(timeline) + 1))
        ws.add_chart(ch, 'E2')

    # ══ DOMAINS ══════════════════════════════════════════════════════════
    if domains:
        ws = wb.create_sheet('Domains')
        ws.append(['DOMAIN', 'QUERIES'])
        for d in domains:
            ws.append([d['qname'], d['n']])
        style_sheet(ws, [56, 14], len(domains))
        for r in range(2, len(domains) + 2):
            ws.cell(row=r, column=1).font = Font(size=9, name='Consolas')
        ws.conditional_formatting.add(
            f"B2:B{len(domains) + 1}",
            DataBarRule(start_type='num', start_value=0, end_type='max',
                        color=ICEDIM, showValue=True))

    # ══ METHODOLOGY ══════════════════════════════════════════════════════
    ws = wb.create_sheet('Methodology')
    ws.append(['RULE', 'THRESHOLD', 'OBSERVED NORMAL (p99)', 'DETECTS'])
    for r in [
        ('port_scan', '15 distinct ports, >50% RST', '3 ports/min', 'TCP SYN scanning'),
        ('connection_burst', '421 connections to one port', '210/min', 'SYN flood, DoS'),
        ('dns_exfil', '30+ char label, entropy >= 3.5', 'entropy ~1.9', 'DNS tunnelling'),
        ('icmp_sweep', '10 distinct destinations', '3 hosts/min', 'Host discovery'),
        ('volume_anomaly', 'z >= 3.5 sigma, floor 50 KB', 'per-host EWMA',
         'Exfiltration, beaconing'),
    ]:
        ws.append(list(r))
    style_sheet(ws, [24, 34, 26, 30], 5)
    ws.cell(row=8, column=1).value = (
        'Thresholds were derived empirically: a baseline capture of ordinary network '
        'activity was analysed, per-minute distributions computed for every metric a '
        'rule depends on, and each threshold set above the 99th percentile of observed '
        'normal traffic — giving a measurable false-positive ceiling by construction.')
    ws.cell(row=8, column=1).font = Font(size=9, italic=True, color=MUTED, name='Calibri')
    ws.merge_cells('A8:D11')
    ws.cell(row=8, column=1).alignment = Alignment(wrap_text=True, vertical='top')

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


if __name__ == '__main__':
    data = build_workbook()
    with open('sentinel_report.xlsx', 'wb') as f:
        f.write(data)
    print(f'wrote sentinel_report.xlsx ({len(data):,} bytes)')
