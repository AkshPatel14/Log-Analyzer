"""
Log Analyzer — IP Blacklist Cross-Reference
Supports local .txt file + optional AbuseIPDB API.
"""
import os
import re
import requests

# Path to bundled blacklist
BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'ip_blacklist.txt')
ABUSEIPDB_API  = 'https://api.abuseipdb.com/api/v2/check'

# In-memory set of blacklisted IPs (loaded once)
_blacklist_set: set = set()


def load_blacklist(filepath: str = None) -> int:
    """Load IP blacklist from a text file into memory. Returns count loaded."""
    global _blacklist_set
    path = filepath or BLACKLIST_FILE
    _blacklist_set = set()

    if not os.path.exists(path):
        return 0

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Match plain IPs (ignore CIDR ranges for now)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                _blacklist_set.add(line)

    return len(_blacklist_set)


def is_blacklisted_local(ip: str) -> bool:
    """Check if an IP is in the local blacklist."""
    if not _blacklist_set:
        load_blacklist()
    return ip in _blacklist_set


def check_ip_abuseipdb(ip: str, api_key: str) -> dict:
    """
    Check an IP against AbuseIPDB.
    Returns dict: { is_blacklisted, abuse_score, country, usage_type, isp }
    """
    if not api_key:
        return {'is_blacklisted': False, 'error': 'No API key configured'}

    try:
        resp = requests.get(
            ABUSEIPDB_API,
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            return {
                'is_blacklisted': score >= 25,
                'abuse_score':    score,
                'country':        data.get('countryCode', ''),
                'usage_type':     data.get('usageType', ''),
                'isp':            data.get('isp', ''),
                'total_reports':  data.get('totalReports', 0),
            }
        return {'is_blacklisted': False, 'error': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'is_blacklisted': False, 'error': str(e)}


def check_ip(ip: str, api_key: str = None) -> dict:
    """Check IP against local blacklist, and optionally AbuseIPDB."""
    local = is_blacklisted_local(ip)
    result = {
        'ip':             ip,
        'is_blacklisted': local,
        'source':         'local' if local else 'none',
        'reason':         'Found in local IP blacklist' if local else '',
        'abuse_score':    None,
        'country':        '',
    }

    if api_key:
        api_result = check_ip_abuseipdb(ip, api_key)
        if api_result.get('is_blacklisted'):
            result['is_blacklisted'] = True
            result['source']         = 'AbuseIPDB'
            result['abuse_score']    = api_result.get('abuse_score')
            result['country']        = api_result.get('country', '')
            result['reason']         = f"AbuseIPDB score: {api_result.get('abuse_score')}%"
        elif not local:
            result['abuse_score'] = api_result.get('abuse_score')
            result['country']     = api_result.get('country', '')

    return result


def cross_reference_threats(threats: list, api_key: str = None) -> list:
    """Update a list of threat dicts with blacklist status."""
    for threat in threats:
        result = check_ip(threat['ip'], api_key)
        threat['is_blacklisted'] = result['is_blacklisted']
        threat['blacklist_source'] = result.get('source', '')
        threat['blacklist_reason'] = result.get('reason', '')
    return threats


def get_blacklist_stats() -> dict:
    """Return stats about the loaded blacklist."""
    if not _blacklist_set:
        load_blacklist()
    return {'total_entries': len(_blacklist_set)}
