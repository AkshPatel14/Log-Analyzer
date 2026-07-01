"""
Log Analyzer — Threat Detector
Identifies: Brute Force, DoS, Path Scan, Suspicious UA, 
            Directory Traversal, SQL Injection, XSS Probes, Admin Probes.
"""
import re
import json
import pandas as pd
from datetime import timedelta

# ─────────────────────────────────────────────
# Thresholds (can be overridden via Settings)
# ─────────────────────────────────────────────
THRESHOLDS = {
    'brute_force_ssh_count':    5,    # failed logins per window
    'brute_force_ssh_window':   60,   # seconds
    'brute_force_http_count':   20,   # 401/403 per window
    'brute_force_http_window':  60,
    'path_scan_count':          30,   # unique paths per window
    'path_scan_window':         60,
    'dos_count':                150,  # requests per window
    'dos_window':               10,
}

# Known malicious/scanner user-agent keywords
SUSPICIOUS_UA_PATTERNS = re.compile(
    r'(sqlmap|nikto|masscan|zgrab|nmap|gobuster|dirbuster|wfuzz|hydra'
    r'|burpsuite|metasploit|python-requests|curl/|wget/|zgrab|libwww-perl'
    r'|scanner|exploit|havij|acunetix|nessus|openvas)',
    re.IGNORECASE
)

# Directory traversal patterns
DIR_TRAVERSAL = re.compile(r'(\.\./|%2e%2e%2f|%252e%252e%252f|\.\.\\)', re.IGNORECASE)

# SQL injection probe keywords
SQLI_PATTERN = re.compile(
    r'(union\s+select|select\s+\*|drop\s+table|insert\s+into'
    r'|or\s+1=1|and\s+1=1|\'--|\'\s+or\s+\'|%27|xp_cmdshell|exec\s*\()',
    re.IGNORECASE
)

# XSS probe patterns
XSS_PATTERN = re.compile(
    r'(<script|javascript:|onerror=|onload=|alert\s*\(|%3cscript|'
    r'expression\s*\(|vbscript:)',
    re.IGNORECASE
)

# Admin/sensitive path probes
ADMIN_PATHS = re.compile(
    r'(/admin|/wp-admin|/phpmyadmin|/manager|/console|/actuator'
    r'|/api/admin|/.env|/config|/backup|/shell|/cmd|/exec'
    r'|/etc/passwd|/wp-login\.php)',
    re.IGNORECASE
)


def _to_ts(val):
    """Safely convert a value to a pandas Timestamp."""
    try:
        return pd.Timestamp(val)
    except Exception:
        return None


def _sliding_window_count(times_sorted, window_seconds):
    """Return the max count of events in any sliding window."""
    if len(times_sorted) < 2:
        return len(times_sorted)
    max_count = 1
    window = timedelta(seconds=window_seconds)
    left = 0
    for right in range(len(times_sorted)):
        while times_sorted[right] - times_sorted[left] > window:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


def detect_threats(df: pd.DataFrame, settings: dict = None) -> list:
    """
    Run all threat detectors on a parsed log DataFrame.
    Returns a list of threat dicts.
    """
    if df.empty:
        return []

    thresh = {**THRESHOLDS, **(settings or {})}
    threats = []

    # Make sure timestamp column is datetime
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df_valid = df.dropna(subset=['timestamp'])

    # ── 1. Brute Force SSH ────────────────────────────────────────────
    ssh_df = df_valid[df_valid['log_type'] == 'ssh']
    if not ssh_df.empty:
        failed_ssh = ssh_df[ssh_df['method'] == 'failed_password']
        for ip, group in failed_ssh.groupby('ip'):
            times = sorted(group['timestamp'].tolist())
            count = _sliding_window_count(times, thresh['brute_force_ssh_window'])
            if count >= thresh['brute_force_ssh_count']:
                evidence = group['raw_line'].head(5).tolist()
                threats.append({
                    'ip':          ip,
                    'threat_type': 'Brute Force SSH',
                    'severity':    'Critical',
                    'count':       len(group),
                    'first_seen':  group['timestamp'].min(),
                    'last_seen':   group['timestamp'].max(),
                    'evidence':    json.dumps(evidence),
                    'is_blacklisted': False
                })

    # ── 2. Brute Force HTTP (401/403) ─────────────────────────────────
    apache_df = df_valid[df_valid['log_type'] == 'apache']
    if not apache_df.empty:
        http_fail = apache_df[apache_df['status'].isin([401, 403])]
        for ip, group in http_fail.groupby('ip'):
            times = sorted(group['timestamp'].tolist())
            count = _sliding_window_count(times, thresh['brute_force_http_window'])
            if count >= thresh['brute_force_http_count']:
                evidence = group['raw_line'].head(5).tolist()
                threats.append({
                    'ip':          ip,
                    'threat_type': 'Brute Force HTTP',
                    'severity':    'Critical',
                    'count':       len(group),
                    'first_seen':  group['timestamp'].min(),
                    'last_seen':   group['timestamp'].max(),
                    'evidence':    json.dumps(evidence),
                    'is_blacklisted': False
                })

    # ── 3. Path / Directory Scanning ─────────────────────────────────
    if not apache_df.empty:
        for ip, group in apache_df.groupby('ip'):
            times = sorted(group['timestamp'].tolist())
            window = timedelta(seconds=thresh['path_scan_window'])
            # Check unique paths in any window
            left = 0
            for right in range(len(times)):
                while times[right] - times[left] > window:
                    left += 1
                slice_group = group.iloc[left:right+1]
                unique_paths = slice_group['path'].nunique()
                if unique_paths >= thresh['path_scan_count']:
                    evidence = slice_group['path'].unique()[:8].tolist()
                    threats.append({
                        'ip':          ip,
                        'threat_type': 'Path Scanning',
                        'severity':    'High',
                        'count':       unique_paths,
                        'first_seen':  group['timestamp'].min(),
                        'last_seen':   group['timestamp'].max(),
                        'evidence':    json.dumps(evidence),
                        'is_blacklisted': False
                    })
                    break

    # ── 4. DoS / Flooding ─────────────────────────────────────────────
    if not df_valid.empty:
        for ip, group in df_valid.groupby('ip'):
            times = sorted(group['timestamp'].tolist())
            count = _sliding_window_count(times, thresh['dos_window'])
            if count >= thresh['dos_count']:
                evidence = [f"{count} requests in {thresh['dos_window']}s window"]
                threats.append({
                    'ip':          ip,
                    'threat_type': 'DoS / Flooding',
                    'severity':    'Critical',
                    'count':       len(group),
                    'first_seen':  group['timestamp'].min(),
                    'last_seen':   group['timestamp'].max(),
                    'evidence':    json.dumps(evidence),
                    'is_blacklisted': False
                })

    # ── 5. Suspicious User-Agent ──────────────────────────────────────
    if not apache_df.empty:
        sus_ua = apache_df[apache_df['user_agent'].str.contains(
            SUSPICIOUS_UA_PATTERNS.pattern, case=False, na=False, regex=True
        )]
        for ip, group in sus_ua.groupby('ip'):
            uas = group['user_agent'].unique()[:5].tolist()
            threats.append({
                'ip':          ip,
                'threat_type': 'Suspicious User-Agent',
                'severity':    'High',
                'count':       len(group),
                'first_seen':  group['timestamp'].min() if not group.empty else None,
                'last_seen':   group['timestamp'].max() if not group.empty else None,
                'evidence':    json.dumps(uas),
                'is_blacklisted': False
            })

    # ── 6. Directory Traversal ────────────────────────────────────────
    if not apache_df.empty:
        trav = apache_df[apache_df['path'].str.contains(
            DIR_TRAVERSAL.pattern, case=False, na=False, regex=True
        )]
        for ip, group in trav.groupby('ip'):
            evidence = group['path'].unique()[:5].tolist()
            threats.append({
                'ip':          ip,
                'threat_type': 'Directory Traversal',
                'severity':    'High',
                'count':       len(group),
                'first_seen':  group['timestamp'].min(),
                'last_seen':   group['timestamp'].max(),
                'evidence':    json.dumps(evidence),
                'is_blacklisted': False
            })

    # ── 7. SQL Injection Probe ────────────────────────────────────────
    if not apache_df.empty:
        sqli = apache_df[apache_df['path'].str.contains(
            SQLI_PATTERN.pattern, case=False, na=False, regex=True
        )]
        for ip, group in sqli.groupby('ip'):
            evidence = group['path'].unique()[:5].tolist()
            threats.append({
                'ip':          ip,
                'threat_type': 'SQL Injection Probe',
                'severity':    'High',
                'count':       len(group),
                'first_seen':  group['timestamp'].min(),
                'last_seen':   group['timestamp'].max(),
                'evidence':    json.dumps(evidence),
                'is_blacklisted': False
            })

    # ── 8. XSS Probe ─────────────────────────────────────────────────
    if not apache_df.empty:
        xss = apache_df[apache_df['path'].str.contains(
            XSS_PATTERN.pattern, case=False, na=False, regex=True
        )]
        for ip, group in xss.groupby('ip'):
            evidence = group['path'].unique()[:5].tolist()
            threats.append({
                'ip':          ip,
                'threat_type': 'XSS Probe',
                'severity':    'Medium',
                'count':       len(group),
                'first_seen':  group['timestamp'].min(),
                'last_seen':   group['timestamp'].max(),
                'evidence':    json.dumps(evidence),
                'is_blacklisted': False
            })

    # ── 9. Admin Panel Probe ──────────────────────────────────────────
    if not apache_df.empty:
        admin = apache_df[apache_df['path'].str.contains(
            ADMIN_PATHS.pattern, case=False, na=False, regex=True
        )]
        for ip, group in admin.groupby('ip'):
            paths = group['path'].unique()[:5].tolist()
            threats.append({
                'ip':          ip,
                'threat_type': 'Admin Panel Probe',
                'severity':    'Medium',
                'count':       len(group),
                'first_seen':  group['timestamp'].min(),
                'last_seen':   group['timestamp'].max(),
                'evidence':    json.dumps(paths),
                'is_blacklisted': False
            })

    # Deduplicate: keep highest-severity threat per IP+type
    seen = set()
    unique_threats = []
    for t in threats:
        key = (t['ip'], t['threat_type'])
        if key not in seen:
            seen.add(key)
            unique_threats.append(t)

    return unique_threats


def severity_score(severity: str) -> int:
    return {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(severity, 0)
