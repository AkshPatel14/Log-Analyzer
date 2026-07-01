"""
Log Analyzer — Report Generator
Exports threats and log summaries to CSV, JSON, and PDF.
"""
import io
import json
import csv
from datetime import datetime


def _fmt(val):
    """Format a value for export."""
    if val is None:
        return ''
    if hasattr(val, 'strftime'):
        return val.strftime('%Y-%m-%d %H:%M:%S')
    return str(val)


# ─────────────────────────────────────────────
# CSV Export
# ─────────────────────────────────────────────
def export_csv(threats: list, log_entries: list = None) -> bytes:
    """Export threats to CSV bytes."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'IP Address', 'Threat Type', 'Severity', 'Count',
        'First Seen', 'Last Seen', 'Blacklisted', 'Blacklist Source',
        'Evidence (sample)'
    ])

    for t in threats:
        evidence = t.get('evidence', '[]')
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = [evidence]
        evidence_str = ' | '.join(str(e) for e in evidence[:3])

        writer.writerow([
            t.get('ip', ''),
            t.get('threat_type', ''),
            t.get('severity', ''),
            t.get('count', 0),
            _fmt(t.get('first_seen')),
            _fmt(t.get('last_seen')),
            'Yes' if t.get('is_blacklisted') else 'No',
            t.get('blacklist_source', ''),
            evidence_str
        ])

    return output.getvalue().encode('utf-8')


# ─────────────────────────────────────────────
# JSON Export
# ─────────────────────────────────────────────
def export_json(threats: list, session_info: dict = None) -> bytes:
    """Export threats to formatted JSON bytes."""
    output = {
        'generated_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'generator':    'Log Analyzer v1.0',
        'session':      session_info or {},
        'total_threats': len(threats),
        'threats': []
    }

    severity_counts = {}
    for t in threats:
        sev = t.get('severity', 'Unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        evidence = t.get('evidence', '[]')
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = [evidence]

        output['threats'].append({
            'ip':               t.get('ip', ''),
            'threat_type':      t.get('threat_type', ''),
            'severity':         t.get('severity', ''),
            'count':            t.get('count', 0),
            'first_seen':       _fmt(t.get('first_seen')),
            'last_seen':        _fmt(t.get('last_seen')),
            'is_blacklisted':   bool(t.get('is_blacklisted', False)),
            'blacklist_source': t.get('blacklist_source', ''),
            'blacklist_reason': t.get('blacklist_reason', ''),
            'evidence':         evidence
        })

    output['severity_summary'] = severity_counts
    return json.dumps(output, indent=2).encode('utf-8')


# ─────────────────────────────────────────────
# PDF Export
# ─────────────────────────────────────────────
def export_pdf(threats: list, session_info: dict = None) -> bytes:
    """Export threats to a formatted PDF incident report."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        # Fallback: return plain text
        return export_csv(threats)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    palette = {
        'dark_bg':   colors.HexColor('#0d1117'),
        'blue':      colors.HexColor('#58a6ff'),
        'red':       colors.HexColor('#f85149'),
        'orange':    colors.HexColor('#d29922'),
        'yellow':    colors.HexColor('#eab308'),
        'green':     colors.HexColor('#3fb950'),
        'text':      colors.HexColor('#e6edf3'),
        'subtext':   colors.HexColor('#8b949e'),
        'border':    colors.HexColor('#30363d'),
        'card':      colors.HexColor('#161b22'),
    }

    severity_colors = {
        'Critical': palette['red'],
        'High':     palette['orange'],
        'Medium':   palette['yellow'],
        'Low':      palette['green'],
    }

    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=22, textColor=palette['blue'],
                                  spaceAfter=6, alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('Sub', parent=styles['Normal'],
                                     fontSize=10, textColor=palette['subtext'],
                                     alignment=TA_CENTER)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'],
                                    fontSize=13, textColor=palette['blue'],
                                    spaceBefore=14, spaceAfter=6)
    normal_style = ParagraphStyle('Body', parent=styles['Normal'],
                                   fontSize=9, textColor=colors.black)

    story = []

    # ── Title ──────────────────────────────────────────────────────────
    story.append(Paragraph('🛡 Log Analyzer — Incident Report', title_style))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')}",
        subtitle_style
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width='100%', thickness=1,
                              color=palette['border'], spaceAfter=12))

    # ── Executive Summary ─────────────────────────────────────────────
    story.append(Paragraph('Executive Summary', heading_style))
    info = session_info or {}
    severity_counts = {}
    for t in threats:
        sev = t.get('severity', 'Unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    blacklisted_count = sum(1 for t in threats if t.get('is_blacklisted'))
    unique_ips = len(set(t.get('ip') for t in threats))

    summary_data = [
        ['Metric', 'Value'],
        ['Log File', info.get('filename', 'N/A')],
        ['Log Type', info.get('log_type', 'N/A').upper()],
        ['Total Threats Detected', str(len(threats))],
        ['Unique Attacking IPs', str(unique_ips)],
        ['Blacklisted IPs', str(blacklisted_count)],
        ['Critical', str(severity_counts.get('Critical', 0))],
        ['High', str(severity_counts.get('High', 0))],
        ['Medium', str(severity_counts.get('Medium', 0))],
        ['Low', str(severity_counts.get('Low', 0))],
    ]

    summary_table = Table(summary_data, colWidths=[9*cm, 7*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), palette['card']),
        ('TEXTCOLOR', (0, 0), (-1, 0), palette['blue']),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('GRID', (0, 0), (-1, -1), 0.5, palette['border']),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # ── Threat Detail Table ───────────────────────────────────────────
    story.append(Paragraph('Detected Threats', heading_style))

    headers = ['IP Address', 'Threat Type', 'Severity', 'Count', 'First Seen', 'Last Seen', 'Blacklisted']
    rows = [headers]
    for t in sorted(threats, key=lambda x: {'Critical':0,'High':1,'Medium':2,'Low':3}.get(x.get('severity','Low'), 4)):
        rows.append([
            t.get('ip', ''),
            t.get('threat_type', ''),
            t.get('severity', ''),
            str(t.get('count', 0)),
            _fmt(t.get('first_seen'))[:16],
            _fmt(t.get('last_seen'))[:16],
            '✓' if t.get('is_blacklisted') else '✗'
        ])

    col_widths = [3.5*cm, 4*cm, 2.2*cm, 1.5*cm, 3.5*cm, 3.5*cm, 2*cm]
    threat_table = Table(rows, colWidths=col_widths, repeatRows=1)
    
    table_style = [
        ('BACKGROUND', (0, 0), (-1, 0), palette['card']),
        ('TEXTCOLOR', (0, 0), (-1, 0), palette['blue']),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.4, palette['border']),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
    ]
    # Color severity cells
    for i, t in enumerate(threats, 1):
        sev = t.get('severity', '')
        sev_color = severity_colors.get(sev)
        if sev_color:
            table_style.append(('TEXTCOLOR', (2, i), (2, i), sev_color))
            table_style.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))

    threat_table.setStyle(TableStyle(table_style))
    story.append(threat_table)
    story.append(Spacer(1, 20))

    # ── Footer ─────────────────────────────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=1,
                              color=palette['border'], spaceBefore=12))
    story.append(Paragraph(
        'Generated by Log Analyzer — Intrusion Detection Analyzer | Confidential',
        ParagraphStyle('footer', parent=styles['Normal'],
                        fontSize=8, textColor=palette['subtext'],
                        alignment=TA_CENTER, spaceBefore=6)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
