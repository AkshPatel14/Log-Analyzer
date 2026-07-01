"""
Log Analyzer — Flask Application Entry Point
Intrusion Detection Log Analyzer
"""
import os
import json
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, send_file, make_response)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import io

from core.parser   import parse_log_content
from core.detector import detect_threats
from core.blacklist import (load_blacklist, check_ip, cross_reference_threats,
                             get_blacklist_stats, is_blacklisted_local)
from core.reporter import export_csv, export_json, export_pdf

# ─────────────────────────────────────────────
# Flask App Configuration
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY']            = 'loganalyzer-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'loganalyzer.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER']         = os.path.join(BASE_DIR, 'data', 'uploads')
app.config['MAX_CONTENT_LENGTH']    = 50 * 1024 * 1024   # 50 MB
app.config['ALLOWED_EXTENSIONS']    = {'log', 'txt'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# ─────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────
class LogSession(db.Model):
    __tablename__ = 'log_sessions'
    id            = db.Column(db.Integer, primary_key=True)
    filename      = db.Column(db.String(255), nullable=False)
    log_type      = db.Column(db.String(50))
    uploaded_at   = db.Column(db.DateTime, default=datetime.utcnow)
    total_entries = db.Column(db.Integer, default=0)
    entries       = db.relationship('LogEntry', backref='session',
                                    lazy=True, cascade='all,delete-orphan')
    threats       = db.relationship('Threat', backref='session',
                                    lazy=True, cascade='all,delete-orphan')


class LogEntry(db.Model):
    __tablename__ = 'log_entries'
    id            = db.Column(db.Integer, primary_key=True)
    session_id    = db.Column(db.Integer, db.ForeignKey('log_sessions.id'), nullable=False)
    ip            = db.Column(db.String(50))
    timestamp     = db.Column(db.DateTime)
    method        = db.Column(db.String(20))
    path          = db.Column(db.String(1000))
    status        = db.Column(db.Integer)
    bytes_sent    = db.Column(db.Integer, default=0)
    user_agent    = db.Column(db.String(500))
    log_type      = db.Column(db.String(20))
    raw_line      = db.Column(db.Text)


class Threat(db.Model):
    __tablename__     = 'threats'
    id                = db.Column(db.Integer, primary_key=True)
    session_id        = db.Column(db.Integer, db.ForeignKey('log_sessions.id'), nullable=False)
    ip                = db.Column(db.String(50))
    threat_type       = db.Column(db.String(100))
    severity          = db.Column(db.String(20))
    count             = db.Column(db.Integer, default=0)
    first_seen        = db.Column(db.DateTime)
    last_seen         = db.Column(db.DateTime)
    evidence          = db.Column(db.Text)    # JSON string
    is_blacklisted    = db.Column(db.Boolean, default=False)
    blacklist_source  = db.Column(db.String(100))
    blacklist_reason  = db.Column(db.String(255))
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)


class AppSettings(db.Model):
    __tablename__ = 'app_settings'
    id    = db.Column(db.Integer, primary_key=True)
    key   = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def allowed_file(filename):
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'])


def get_setting(key, default=''):
    s = AppSettings.query.filter_by(key=key).first()
    return s.value if s else default


def set_setting(key, value):
    s = AppSettings.query.filter_by(key=key).first()
    if s:
        s.value = value
    else:
        db.session.add(AppSettings(key=key, value=value))
    db.session.commit()


def severity_order(sev):
    return {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(sev, 4)


def _process_log(content, filename, log_type_hint=None):
    """Parse, detect, blacklist-check and store a log file. Returns LogSession."""
    df, log_type = parse_log_content(content, log_type_hint)
    if df.empty:
        return None, 'Could not parse the log file. Please ensure it is Apache or SSH format.'

    # Create session
    session = LogSession(filename=filename, log_type=log_type,
                         total_entries=len(df))
    db.session.add(session)
    db.session.flush()

    # Save entries (batch insert, up to 5000 rows to keep it fast)
    batch = []
    for _, row in df.head(5000).iterrows():
        ts = row.get('timestamp')
        if hasattr(ts, 'to_pydatetime'):
            ts = ts.to_pydatetime()
        batch.append(LogEntry(
            session_id = session.id,
            ip         = str(row.get('ip', '')),
            timestamp  = ts,
            method     = str(row.get('method', '')),
            path       = str(row.get('path', ''))[:999],
            status     = int(row.get('status', 0)),
            bytes_sent = int(row.get('bytes_sent', 0)),
            user_agent = str(row.get('user_agent', ''))[:499],
            log_type   = str(row.get('log_type', '')),
            raw_line   = str(row.get('raw_line', ''))
        ))
    db.session.bulk_save_objects(batch)

    # Run threat detection
    api_key = get_setting('abuseipdb_key', '')
    threat_dicts = detect_threats(df)
    threat_dicts = cross_reference_threats(threat_dicts, api_key or None)

    for t in threat_dicts:
        fs = t.get('first_seen')
        ls = t.get('last_seen')
        if hasattr(fs, 'to_pydatetime'): fs = fs.to_pydatetime()
        if hasattr(ls, 'to_pydatetime'): ls = ls.to_pydatetime()
        db.session.add(Threat(
            session_id       = session.id,
            ip               = t.get('ip', ''),
            threat_type      = t.get('threat_type', ''),
            severity         = t.get('severity', 'Low'),
            count            = t.get('count', 0),
            first_seen       = fs,
            last_seen        = ls,
            evidence         = t.get('evidence', '[]'),
            is_blacklisted   = bool(t.get('is_blacklisted', False)),
            blacklist_source = t.get('blacklist_source', ''),
            blacklist_reason = t.get('blacklist_reason', '')
        ))

    db.session.commit()
    load_blacklist()  # refresh blacklist in memory
    return session, None


# ─────────────────────────────────────────────
# ── DASHBOARD ──────────────────────────────────
# ─────────────────────────────────────────────
@app.route('/')
def dashboard():
    sessions     = LogSession.query.order_by(LogSession.uploaded_at.desc()).all()
    total_sessions = len(sessions)

    all_threats  = Threat.query.all()
    total_threats = len(all_threats)
    total_ips     = db.session.query(db.func.count(db.func.distinct(Threat.ip))).scalar() or 0
    blacklisted   = Threat.query.filter_by(is_blacklisted=True).count()

    severity_counts = {
        'Critical': Threat.query.filter_by(severity='Critical').count(),
        'High':     Threat.query.filter_by(severity='High').count(),
        'Medium':   Threat.query.filter_by(severity='Medium').count(),
        'Low':      Threat.query.filter_by(severity='Low').count(),
    }

    threat_types = {}
    for t in all_threats:
        threat_types[t.threat_type] = threat_types.get(t.threat_type, 0) + 1

    recent_threats = (Threat.query
                      .order_by(Threat.created_at.desc())
                      .limit(10).all())

    recent_sessions = sessions[:5]

    return render_template('dashboard.html',
        total_sessions=total_sessions,
        total_threats=total_threats,
        total_ips=total_ips,
        blacklisted=blacklisted,
        severity_counts=severity_counts,
        threat_types=threat_types,
        recent_threats=recent_threats,
        recent_sessions=recent_sessions
    )


# ─────────────────────────────────────────────
# ── LOG MANAGEMENT ─────────────────────────────
# ─────────────────────────────────────────────
@app.route('/logs')
def logs():
    sessions = LogSession.query.order_by(LogSession.uploaded_at.desc()).all()
    return render_template('logs.html', sessions=sessions)


@app.route('/logs/upload', methods=['POST'])
def upload_log():
    if 'logfile' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('logs'))

    f = request.files['logfile']
    if f.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('logs'))

    if not allowed_file(f.filename):
        flash('Only .log and .txt files are allowed.', 'danger')
        return redirect(url_for('logs'))

    filename = secure_filename(f.filename)
    content  = f.read().decode('utf-8', errors='ignore')

    session, error = _process_log(content, filename)
    if error:
        flash(error, 'danger')
        return redirect(url_for('logs'))

    threat_count = len(session.threats)
    flash(f'✅ "{filename}" loaded — {session.total_entries} entries, {threat_count} threats detected.', 'success')
    return redirect(url_for('logs'))


@app.route('/logs/sample/<log_type>')
def load_sample(log_type):
    data_dir = os.path.join(BASE_DIR, 'data')
    if log_type == 'apache':
        path, name = os.path.join(data_dir, 'sample_apache.log'), 'sample_apache.log'
    elif log_type == 'ssh':
        path, name = os.path.join(data_dir, 'sample_ssh.log'), 'sample_ssh.log'
    else:
        flash('Unknown log type.', 'danger')
        return redirect(url_for('logs'))

    if not os.path.exists(path):
        flash('Sample file not found.', 'danger')
        return redirect(url_for('logs'))

    with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
        content = fp.read()

    session, error = _process_log(content, name, log_type)
    if error:
        flash(error, 'danger')
        return redirect(url_for('logs'))

    flash(f'✅ Sample {log_type.upper()} log loaded — {session.total_entries} entries, {len(session.threats)} threats detected.', 'success')
    return redirect(url_for('logs'))


@app.route('/logs/delete/<int:session_id>', methods=['POST'])
def delete_session(session_id):
    session = LogSession.query.get_or_404(session_id)
    db.session.delete(session)
    db.session.commit()
    flash(f'Session "{session.filename}" deleted.', 'info')
    return redirect(url_for('logs'))


@app.route('/api/logs/<int:session_id>')
def api_logs(session_id):
    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    ip_filter= request.args.get('ip', '')
    status_f = request.args.get('status', '')

    q = LogEntry.query.filter_by(session_id=session_id)
    if ip_filter:
        q = q.filter(LogEntry.ip.contains(ip_filter))
    if status_f:
        try:
            q = q.filter_by(status=int(status_f))
        except ValueError:
            pass

    total    = q.count()
    entries  = q.order_by(LogEntry.id).offset((page-1)*per_page).limit(per_page).all()

    return jsonify({
        'total': total,
        'page':  page,
        'pages': (total + per_page - 1) // per_page,
        'data': [{
            'ip':         e.ip,
            'timestamp':  e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '',
            'method':     e.method,
            'path':       e.path,
            'status':     e.status,
            'bytes_sent': e.bytes_sent,
            'user_agent': e.user_agent,
            'log_type':   e.log_type,
            'raw_line':   e.raw_line
        } for e in entries]
    })


# ─────────────────────────────────────────────
# ── THREATS ────────────────────────────────────
# ─────────────────────────────────────────────
@app.route('/threats')
def threats():
    sessions     = LogSession.query.all()
    session_id   = request.args.get('session_id', type=int)
    severity_f   = request.args.get('severity', '')
    type_f       = request.args.get('type', '')

    q = Threat.query
    if session_id:
        q = q.filter_by(session_id=session_id)
    if severity_f:
        q = q.filter_by(severity=severity_f)
    if type_f:
        q = q.filter_by(threat_type=type_f)

    all_threats = q.order_by(Threat.created_at.desc()).all()

    threat_types = db.session.query(
        db.func.distinct(Threat.threat_type)
    ).all()
    threat_types = [t[0] for t in threat_types]

    return render_template('threats.html',
        threats=all_threats,
        sessions=sessions,
        selected_session=session_id,
        selected_severity=severity_f,
        selected_type=type_f,
        threat_types=threat_types
    )


@app.route('/api/threats')
def api_threats():
    session_id = request.args.get('session_id', type=int)
    q = Threat.query
    if session_id:
        q = q.filter_by(session_id=session_id)

    threats = q.order_by(Threat.severity).all()
    return jsonify([{
        'id':               t.id,
        'ip':               t.ip,
        'threat_type':      t.threat_type,
        'severity':         t.severity,
        'count':            t.count,
        'first_seen':       t.first_seen.strftime('%Y-%m-%d %H:%M:%S') if t.first_seen else '',
        'last_seen':        t.last_seen.strftime('%Y-%m-%d %H:%M:%S')  if t.last_seen  else '',
        'is_blacklisted':   t.is_blacklisted,
        'blacklist_source': t.blacklist_source or '',
        'blacklist_reason': t.blacklist_reason or '',
        'evidence':         json.loads(t.evidence) if t.evidence else []
    } for t in threats])


@app.route('/api/threats/stats')
def api_threat_stats():
    session_id = request.args.get('session_id', type=int)
    q = Threat.query
    if session_id:
        q = q.filter_by(session_id=session_id)

    threats = q.all()
    by_severity  = {}
    by_type      = {}
    by_ip        = {}

    for t in threats:
        by_severity[t.severity]   = by_severity.get(t.severity, 0) + 1
        by_type[t.threat_type]    = by_type.get(t.threat_type, 0) + 1
        by_ip[t.ip]               = by_ip.get(t.ip, 0) + t.count

    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        'by_severity': by_severity,
        'by_type':     by_type,
        'top_ips':     [{'ip': ip, 'count': cnt} for ip, cnt in top_ips]
    })


# ─────────────────────────────────────────────
# ── VISUALIZER ─────────────────────────────────
# ─────────────────────────────────────────────
@app.route('/visualizer')
def visualizer():
    sessions = LogSession.query.all()
    return render_template('visualizer.html', sessions=sessions)


@app.route('/api/charts/timeline')
def api_timeline():
    session_id = request.args.get('session_id', type=int)
    granularity = request.args.get('granularity', 'hour')  # 'minute' or 'hour'

    q = LogEntry.query.filter(LogEntry.timestamp.isnot(None))
    if session_id:
        q = q.filter_by(session_id=session_id)

    entries = q.order_by(LogEntry.timestamp).all()

    buckets = {}
    for e in entries:
        if not e.timestamp:
            continue
        if granularity == 'minute':
            key = e.timestamp.strftime('%H:%M')
        else:
            key = e.timestamp.strftime('%d/%m %H:00')
        buckets[key] = buckets.get(key, 0) + 1

    labels = sorted(buckets.keys())
    data   = [buckets[l] for l in labels]
    return jsonify({'labels': labels, 'data': data})


@app.route('/api/charts/top-ips')
def api_top_ips():
    session_id = request.args.get('session_id', type=int)
    q = LogEntry.query
    if session_id:
        q = q.filter_by(session_id=session_id)

    results = (db.session.query(LogEntry.ip, db.func.count(LogEntry.id).label('cnt'))
               .filter(LogEntry.ip.isnot(None))
               .group_by(LogEntry.ip)
               .order_by(db.desc('cnt'))
               .limit(10).all())

    return jsonify({
        'labels': [r.ip   for r in results],
        'data':   [r.cnt  for r in results]
    })


@app.route('/api/charts/status-codes')
def api_status_codes():
    session_id = request.args.get('session_id', type=int)
    q = LogEntry.query.filter(LogEntry.status.isnot(None), LogEntry.status > 0)
    if session_id:
        q = q.filter_by(session_id=session_id)

    results = (db.session.query(LogEntry.status, db.func.count(LogEntry.id).label('cnt'))
               .filter(LogEntry.status.isnot(None))
               .group_by(LogEntry.status)
               .order_by(LogEntry.status).all())

    return jsonify({
        'labels': [str(r.status) for r in results],
        'data':   [r.cnt          for r in results]
    })


@app.route('/api/charts/threat-types')
def api_threat_types():
    session_id = request.args.get('session_id', type=int)
    q = Threat.query
    if session_id:
        q = q.filter_by(session_id=session_id)

    results = (db.session.query(Threat.threat_type,
                                db.func.count(Threat.id).label('cnt'))
               .group_by(Threat.threat_type).all())

    return jsonify({
        'labels': [r.threat_type for r in results],
        'data':   [r.cnt          for r in results]
    })


# ─────────────────────────────────────────────
# ── BLACKLIST ──────────────────────────────────
# ─────────────────────────────────────────────
@app.route('/blacklist')
def blacklist():
    stats = get_blacklist_stats()
    blacklisted_threats = (Threat.query
                           .filter_by(is_blacklisted=True)
                           .order_by(Threat.created_at.desc()).all())
    api_key = get_setting('abuseipdb_key', '')
    return render_template('blacklist.html',
        stats=stats,
        blacklisted_threats=blacklisted_threats,
        api_key=api_key
    )


@app.route('/api/blacklist/check', methods=['POST'])
def api_check_ip():
    data    = request.get_json() or {}
    ip      = data.get('ip', '').strip()
    api_key = get_setting('abuseipdb_key', '')

    if not ip:
        return jsonify({'error': 'No IP provided'}), 400

    result = check_ip(ip, api_key or None)
    return jsonify(result)


@app.route('/blacklist/reload', methods=['POST'])
def reload_blacklist():
    count = load_blacklist()
    flash(f'✅ Blacklist reloaded — {count} IPs loaded.', 'success')
    return redirect(url_for('blacklist'))


@app.route('/blacklist/settings', methods=['POST'])
def save_blacklist_settings():
    api_key = request.form.get('abuseipdb_key', '').strip()
    set_setting('abuseipdb_key', api_key)
    flash('✅ API key saved successfully.', 'success')
    return redirect(url_for('blacklist'))


# ─────────────────────────────────────────────
# ── REPORTS ────────────────────────────────────
# ─────────────────────────────────────────────
@app.route('/reports')
def reports():
    sessions = LogSession.query.order_by(LogSession.uploaded_at.desc()).all()
    return render_template('reports.html', sessions=sessions)


@app.route('/reports/export', methods=['POST'])
def export_report():
    fmt        = request.form.get('format', 'csv')
    session_id = request.form.get('session_id', type=int)
    severity_f = request.form.get('severity', '')

    q = Threat.query
    if session_id:
        q = q.filter_by(session_id=session_id)
    if severity_f:
        q = q.filter_by(severity=severity_f)

    threats = q.all()
    threat_dicts = [{
        'ip':               t.ip,
        'threat_type':      t.threat_type,
        'severity':         t.severity,
        'count':            t.count,
        'first_seen':       t.first_seen,
        'last_seen':        t.last_seen,
        'is_blacklisted':   t.is_blacklisted,
        'blacklist_source': t.blacklist_source or '',
        'blacklist_reason': t.blacklist_reason or '',
        'evidence':         t.evidence
    } for t in threats]

    session_info = {}
    if session_id:
        s = LogSession.query.get(session_id)
        if s:
            session_info = {
                'filename': s.filename,
                'log_type': s.log_type,
                'uploaded_at': s.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
            }

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

    if fmt == 'csv':
        data = export_csv(threat_dicts)
        resp = make_response(data)
        resp.headers['Content-Type']        = 'text/csv'
        resp.headers['Content-Disposition'] = f'attachment; filename=loganalyzer_report_{ts}.csv'
        return resp

    elif fmt == 'json':
        data = export_json(threat_dicts, session_info)
        resp = make_response(data)
        resp.headers['Content-Type']        = 'application/json'
        resp.headers['Content-Disposition'] = f'attachment; filename=loganalyzer_report_{ts}.json'
        return resp

    elif fmt == 'pdf':
        data = export_pdf(threat_dicts, session_info)
        resp = make_response(data)
        resp.headers['Content-Type']        = 'application/pdf'
        resp.headers['Content-Disposition'] = f'attachment; filename=loganalyzer_report_{ts}.pdf'
        return resp

    flash('Invalid export format.', 'danger')
    return redirect(url_for('reports'))


# ─────────────────────────────────────────────
# App Init
# ─────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        load_blacklist()   # pre-load blacklist into memory
    app.run(debug=True, host='127.0.0.1', port=5000)
