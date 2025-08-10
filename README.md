![Version](https://img.shields.io/badge/version-2.0.0-blue) ![Python](https://img.shields.io/badge/python-3.8%2B-green) ![License](https://img.shields.io/badge/license-MIT-orange) ![Last Updated](https://img.shields.io/badge/last%20updated-2025--08--04-lightgrey)

# Python-Security-Tools ![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)
tools, rules, and customised scripts walkthroughs by Python


## 🔐 Password Strength Analyzer – Version 2.0

A next-generation password security tool offering **advanced analysis, real-time feedback, and GUI enhancements**. Version 2.0 introduces improved detection algorithms, a memory-efficient dictionary handler for large wordlists (including `rockyou.txt`), and refined password vulnerability insights.

### ✅ Key Enhancements

* **Comprehensive Security Checks:** Detects dictionary matches, repetitive patterns, sequences, and evaluates entropy.
* **Enhanced GUI Dashboard:** Visual strength indicators, particle animations, clipboard support, and progress bars.
* **Efficient Dictionary Management:** Supports 10M+ passwords with optimized memory usage.
* **Actionable Security Insights:** Estimated crack times, detailed feedback, and improvement recommendations.

### 📂 Resources

* **🔗 [Pull Request for Version 2.0](https://github.com/Sree-Ajitha/Python-Security-Tools/pull/1#issue-3288836333).**
* **⬇ [Download Password Strength Analyzer v2.0 (.py)](https://github.com/Sree-Ajitha/Python-Security-Tools/compare/Sree-Ajitha-password_checker_V2.0)**
---
# Log Parser and Suspicious IP Detection Tool

A Python tool for parsing server logs and identifying potentially suspicious IP addresses based on various behavioral patterns and detection criteria.

## Features

- Parse common log formats (Apache, Nginx, Auth logs)
- Detect suspicious activity based on multiple criteria:
  - High request volume
  - Failed login attempts
  - Access to sensitive paths
  - HTTP error responses
  - Regular request patterns (bot detection)
- IP address whitelisting and blacklisting
- Multiple report formats (text, JSON, CSV)

## Requirements

- Python 3.6+

## Installation

1. Clone this repository or  **⬇[Download log_analyzer (.py)](https://github.com/Sree-Ajitha/Python-Security-Tools/blob/fd303dc2f59b45781e392ea14b02a84bbcd48434/log_analyzer.py)**
2. Make the script executable:
   ```bash
   chmod +x log_analyzer.py
   ```

## Usage

### Basic Usage

```bash
python log_analyzer.py --log-file /var/log/apache2/access.log --log-type apache
```

### With Additional Options

```bash
python log_analyzer.py \
  --log-file /var/log/auth.log \
  --log-type auth \
  --output suspicious_ips.json \
  --format json \
  --threshold-requests 150 \
  --threshold-logins 3 \
  --whitelist 192.168.1.1,10.0.0.1 \
  --sensitive-paths /phpmyadmin,/wp-admin,/config
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--log-file`, `-f` | Log file to analyze (required) |
| `--log-type`, `-t` | Type of log file (apache, nginx, auth, generic) |
| `--output`, `-o` | Output file for the report (optional, prints to console if not specified) |
| `--format` | Output format (text, json, csv) |
| `--threshold-requests` | Request threshold for suspicious activity (default: 100) |
| `--threshold-logins` | Failed login threshold for suspicious activity (default: 5) |
| `--whitelist` | Comma-separated list of whitelisted IPs |
| `--blacklist` | Comma-separated list of blacklisted IPs |
| `--sensitive-paths` | Comma-separated list of additional sensitive paths to monitor |

## Example Report (Text Format)

```
=== Suspicious IP Activity Report ===
Generated at: 2025-08-07T19:58:23.123456
Total suspicious IPs: 2

1. 192.168.1.100
   - Multiple failed logins: 7 attempts
   - Total requests: 12

2. 203.0.113.42
   - High request volume: 567 requests
   - Accessed sensitive paths: /admin, /wp-login
   - Multiple 4xx errors: 45 responses
   - Suspiciously regular request pattern (potential bot)
   - Total requests: 567
   - Status codes: 200: 498, 404: 42, 403: 3
```

## Adding Custom Log Formats

To add support for a custom log format, you can modify the `log_patterns` dictionary in the script:

```python
analyzer = LogAnalyzer({
    'log_patterns': {
        'custom': r'your_regex_pattern_here'
    }
})
analyzer.parse_log_file('your_log_file.log', 'custom')
```

## Future Enhancements

- GeoIP integration for location-based analysis
- Real-time log monitoring mode
- Automatic firewall rule generation
- Web interface for visualization

---

## 🚧 Development Roadmap

- [x] Initial repo setup
- [x] Uploaded base scripts
- [ ] Add full documentation
- [ ] Create Splunk dashboardshttps://github.com/Sree-Ajitha/Python-Security-Tools/pull/1#issue-3288836333
- [ ] Write blog post walkthrough

> **Note:** This project is currently **In Progress**.  
> New features, updated scripts, and documentation will be added over the coming weeks.  
> Feedback and collaboration are welcome.
