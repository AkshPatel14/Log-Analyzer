# Log Analyzer 🛡️

**Log Analyzer** is a premium, lightweight, web-based **Intrusion Detection Log Analyzer** built with Flask, Pandas, and SQLite. It enables security administrators, systems engineers, and developer teams to easily upload, parse, and analyze server logs to identify cyber threats, bad actors, brute force attacks, and system vulnerabilities in real-time.

---

## 🚀 Key Features

*   **⚡ Automatic Log Parsing**:
    *   Supports **Apache Combined Log Format** (HTTP/HTTPS access logs).
    *   Supports **SSH auth logs** (`/var/log/auth.log` format).
    *   Intelligent automatic format detection on upload.
*   **🔍 Threat Detection Engine**:
    *   **Brute Force SSH & HTTP**: Identifies rapid login failures within a custom sliding window.
    *   **Denial of Service (DoS)**: Flags massive traffic spikes per client IP in sub-minute windows.
    *   **SQL Injection (SQLi) Probes**: Detects common malicious SQL query structures (e.g., `UNION SELECT`, `1=1`, etc.).
    *   **Cross-Site Scripting (XSS) Probes**: Screens paths and parameters for script injection signatures.
    *   **Directory Traversal**: Traces attempts to access paths with `../` or URL-encoded variations.
    *   **Admin Console Probes**: Detects scanning of sensitive entry points (e.g., `/admin`, `/.env`, `/wp-login.php`).
    *   **Malicious User Agents**: Flags request headers associated with automated tools (e.g., Nikto, Sqlmap, Nmap, curl, etc.).
*   **📊 Interactive Visualization Dashboard**:
    *   Stunning, responsive UI featuring threat timeline charts.
    *   Aggregated graphs outlining **Threat Severity distribution** (High, Medium, Low) and **Common Threat Types**.
    *   Detailed inspection tables grouping events by attacker IP.
*   **🔗 Reputation Cross-Referencing**:
    *   **Local Blacklist**: Direct lookup using pre-loaded high-risk IP lists (`data/ip_blacklist.txt`).
    *   **AbuseIPDB Integration**: Optional API connectivity for real-time validation of attacker IPs against active reporting databases.
*   **📄 Professional Reports**:
    *   Export parsed threats and metadata to structured **PDF Reports**, **CSV spreadsheets**, or raw **JSON** documents.

---

## 📁 Repository Structure

```text
Internship_Project/
├── app.py                     # Flask application entry point (Routes, Models, DB setup)
├── core/
│   ├── __init__.py            # Python package initialization
│   ├── parser.py              # Log format auto-detector and regex parsers
│   ├── detector.py            # Custom sliding-window & signature threat detection logic
│   ├── blacklist.py           # IP cross-referencing (local files & AbuseIPDB API)
│   └── reporter.py            # PDF, CSV, and JSON report compilation logic
├── data/
│   ├── generate_samples.py    # CLI tool to generate realistic threat-ridden sample logs
│   ├── ip_blacklist.txt       # Local dictionary of blacklisted IPs
│   ├── sample_apache.log      # Pre-generated sample Apache log file
│   └── sample_ssh.log         # Pre-generated sample SSH log file
├── static/
│   ├── css/
│   │   └── style.css          # Core UI design sheets and custom styling tokens
│   └── js/
│   │       ├── dashboard.js   # Dashboard statistics handlers
│   │       ├── logs.js        # Log search/filter mechanisms
│   │       ├── main.js        # General UI setup code
│   │       ├── threats.js     # Threat assessment components
│   │       └── visualizer.js  # Chart logic (Chart.js integrations)
├── templates/
│   ├── base.html              # Core navigation layout and assets wrapper
│   ├── dashboard.html         # Main dashboard analytics grid
│   ├── logs.html              # Searchable log database browser
│   ├── threats.html           # Attacker threat analysis grid
│   ├── blacklist.html         # Blacklist database manager UI
│   ├── reports.html           # Report exporter controls
│   └── visualizer.html        # Interactive chart visualizer interface
├── requirements.txt           # Project package dependencies
└── README.md                  # Project documentation (this file)
```

---

## 🛠️ Installation & Getting Started

Follow these steps to set up and run Log Analyzer on your local machine:

### 1. Prerequisites
Ensure you have **Python 3.8+** installed.

### 2. Clone and Navigate
```bash
git clone <your-repository-url>
cd Internship_Project
```

### 3. Create a Virtual Environment
Initialize a clean Python virtual environment to manage dependencies:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
Install all package requirements defined in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 5. Running the Application
Launch the Flask development server:
```bash
python app.py
```
By default, the server runs locally at: **`http://127.0.0.1:5000/`**

On startup, Log Analyzer will automatically:
1. Initialize the SQLite database (`loganalyzer.db`).
2. Generate all database tables via SQLAlchemy.
3. Pre-load the local IP blacklist into memory.

---

## 🧪 Testing with Mock Data

To quickly evaluate the analyzer's capabilities without real production logs, you can run the built-in sample generator:

1. Generate realistic Apache and SSH threat-ridden logs:
   ```bash
   python data/generate_samples.py
   ```
2. This creates:
   *   `data/sample_apache.log` (~1000 lines of typical web traffic mixed with directory traversal, DoS, SQL injection, and XSS scanner activity).
   *   `data/sample_ssh.log` (~500 lines of normal authentications mixed with brute-force authentication attacks).
3. Access the Log Analyzer web UI (`http://127.0.0.1:5000/`), click **Upload**, and select either of these logs to instantly visualize detected threats!

---

## ⚙️ Customizing Settings

All configurations can be customized inside the Web UI settings panel:
*   **Threshold Modification**: Customize brute force request counts, sliding window durations, and DoS alert parameters.
*   **IP Intelligence API**: Add your [AbuseIPDB API Key](https://www.abuseipdb.com/) to automatically cross-reference suspicious IPs with active abuse intelligence databases.
*   **Blacklist Management**: Upload raw custom IP blocklists to dynamically protect your local ruleset.

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
