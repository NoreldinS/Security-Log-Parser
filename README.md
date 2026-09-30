
# Security Log Parser & SIEM Dashboard

A lightweight, full-stack security event analysis tool that parses raw web server logs, detects threat vectors and brute-force attempts, and renders live alerts on a browser dashboard.

## Features

- **Regex Log Parsing:** Parses timestamps, log levels, IP addresses, and HTTP payloads.
- **Signature Threat Detection:** Identifies common web application attack signatures including SQL Injection, Cross-Site Scripting (XSS), Path Traversal, Command Injection, and vulnerability scanners.
- **Stateful Brute-Force Tracking:** Tracks failed login attempts per IP address and flags threshold breaches as CRITICAL alerts.
- **Dual JSON Output:** Generates granular alert records (`alertfile.json`) alongside category metrics (`count.json`).
- **Dynamic UI Dashboard:** Displays parsed threat events and statistics in a clean web visualizer (`attackPage.html`).

## Technologies

- Python 3.x
- JavaScript (Fetch API / DOM Manipulation)
- HTML5 / CSS3
- JSON
- Built-in Python libraries: `re`, `json`, `collections`

No external `pip` dependencies are required.

## How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/NoreldinS/Security-Log-Parser.git
cd Security-Log-Parser
```
### 2. Run the Log Parser
``` bash
python3 parser.py
```
### Expected Log Format
```text
2026-09-30 10:01:03 [WARN] 185.220.101.5 GET /login.php?user=' OR 1=1--
2026-09-30 10:02:15 [ERROR] 198.51.100.77 Failed login attempt
```
Launch the dashboard UI: Open attackPage.html directly in your web browser, or launch it using VS Code's Live Server extension.
