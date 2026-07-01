"""
Log Analyzer — Log Parser
Supports Apache Combined Log Format and SSH auth.log format.
"""
import re
import pandas as pd
from datetime import datetime

# ─────────────────────────────────────────────
# Apache Combined Log Format regex
# ─────────────────────────────────────────────
APACHE_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*?)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*?)"\s+"(?P<user_agent>[^"]*?)")?'
)

# ─────────────────────────────────────────────
# SSH auth.log regex patterns
# ─────────────────────────────────────────────
SSH_TIMESTAMP   = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
SSH_FAILED      = re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)')
SSH_INVALID     = re.compile(r'Invalid user (\S+) from ([\d\.]+)')
SSH_ACCEPTED    = re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)')
SSH_ROOT        = re.compile(r'ROOT LOGIN REFUSED from ([\d\.]+)')
SSH_DISCONNECT  = re.compile(r'Received disconnect from ([\d\.]+) port \d+:11:')

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5,  'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def detect_log_type(content: str) -> str:
    """Auto-detect whether the log is Apache or SSH format."""
    sample = content[:3000]
    if re.search(r'HTTP/\d\.\d', sample):
        return 'apache'
    if re.search(r'(Failed password|Invalid user|Accepted password|sshd\[\d+\])', sample):
        return 'ssh'
    return 'unknown'


# ─────────────────────────────────────────────
# Apache parser
# ─────────────────────────────────────────────
def parse_apache_log(content: str) -> pd.DataFrame:
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        m = APACHE_PATTERN.match(line)
        if not m:
            continue

        # Parse timestamp
        try:
            ts_raw = m.group('time')[:20]           # "15/Jan/2024:10:23:01"
            timestamp = datetime.strptime(ts_raw, '%d/%b/%Y:%H:%M:%S')
        except Exception:
            timestamp = None

        # Parse request line
        request = m.group('request') or ''
        parts   = request.split(' ')
        method  = parts[0] if len(parts) > 0 else ''
        path    = parts[1] if len(parts) > 1 else ''

        try:
            status = int(m.group('status'))
        except Exception:
            status = 0

        try:
            bytes_sent = int(m.group('bytes'))
        except Exception:
            bytes_sent = 0

        entries.append({
            'ip':         m.group('ip'),
            'timestamp':  timestamp,
            'method':     method,
            'path':       path,
            'status':     status,
            'bytes_sent': bytes_sent,
            'referer':    m.group('referer')    or '',
            'user_agent': m.group('user_agent') or '',
            'log_type':   'apache',
            'raw_line':   line
        })

    return pd.DataFrame(entries) if entries else pd.DataFrame(
        columns=['ip','timestamp','method','path','status','bytes_sent',
                 'referer','user_agent','log_type','raw_line'])


# ─────────────────────────────────────────────
# SSH parser
# ─────────────────────────────────────────────
def parse_ssh_log(content: str) -> pd.DataFrame:
    entries = []
    current_year = datetime.now().year

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse timestamp
        timestamp = None
        ts_m = SSH_TIMESTAMP.match(line)
        if ts_m:
            try:
                ts_str = ts_m.group(1).split()
                month  = MONTH_MAP.get(ts_str[0], 1)
                day    = int(ts_str[1])
                h, mi, s = map(int, ts_str[2].split(':'))
                timestamp = datetime(current_year, month, day, h, mi, s)
            except Exception:
                pass

        # Match event type
        event_type = None
        ip = user = None

        for pattern, etype in [
            (SSH_FAILED,     'failed_password'),
            (SSH_INVALID,    'invalid_user'),
            (SSH_ACCEPTED,   'accepted'),
            (SSH_ROOT,       'root_refused'),
            (SSH_DISCONNECT, 'disconnect'),
        ]:
            em = pattern.search(line)
            if em:
                groups = em.groups()
                if etype in ('failed_password', 'accepted'):
                    user, ip = groups[0], groups[1]
                elif etype == 'invalid_user':
                    user, ip = groups[0], groups[1]
                elif etype in ('root_refused', 'disconnect'):
                    ip = groups[0]
                event_type = etype
                break

        if ip and event_type:
            status = 200 if event_type == 'accepted' else 401
            entries.append({
                'ip':         ip,
                'timestamp':  timestamp,
                'method':     event_type,
                'path':       f'/ssh/{event_type}',
                'status':     status,
                'bytes_sent': 0,
                'referer':    '',
                'user_agent': user or '',
                'log_type':   'ssh',
                'raw_line':   line
            })

    return pd.DataFrame(entries) if entries else pd.DataFrame(
        columns=['ip','timestamp','method','path','status','bytes_sent',
                 'referer','user_agent','log_type','raw_line'])


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────
def parse_log_content(content: str, log_type: str = None):
    """Parse log content. Returns (DataFrame, detected_log_type)."""
    if log_type is None:
        log_type = detect_log_type(content)

    if log_type == 'apache':
        return parse_apache_log(content), 'apache'
    elif log_type == 'ssh':
        return parse_ssh_log(content), 'ssh'
    else:
        return pd.DataFrame(), 'unknown'
