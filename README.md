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
# **🛡 [Log Parser & Suspicious IP Detector – Python Tool](https://github.com/Sree-Ajitha/Python-Security-Tools/blob/1a1380dd739b0cf51c35afcb12ac1275d4d24324/Log%20Parser%20%26%20IP%20Detection%20Tool.md)**

A lightweight yet powerful Python-based security utility that parses server logs and flags potentially malicious IP addresses using multi-criteria detection algorithms. Supports Apache, Nginx, Auth, and generic log formats.
✅ Core Capabilities

* Multi-Pattern Threat Detection: High request spikes, failed logins, sensitive path access, HTTP error anomalies, and bot-like behavior.

* Flexible Whitelisting/Blacklisting: Custom IP inclusion/exclusion lists for precise filtering.

* Multiple Output Formats: Generate text, JSON, or CSV reports for easy integration.

*Customizable Thresholds: Fine-tune activity limits for requests and login attempts.

📂 Resources

**⬇[Download log_analyzer (.py)](https://github.com/Sree-Ajitha/Python-Security-Tools/blob/fd303dc2f59b45781e392ea14b02a84bbcd48434/log_analyzer.py)**

💻 Basic Usage:

python log_analyzer.py --log-file /var/log/apache2/access.log --log-type apache

Sample:

=== Suspicious IP Activity Report ===
Total suspicious IPs: 2
1. 192.168.1.100 - Multiple failed logins: 7
2. 203.0.113.42 - High request volume: 567, Sensitive paths: /admin, /wp-login

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
