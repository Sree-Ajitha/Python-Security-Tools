# Ransomware Activity Detection Script

This script monitors file system activities to detect potential ransomware behavior. It's designed as a basic detection tool that can alert you to suspicious file operations that might indicate ransomware activity.

## Disclaimer

This is a **basic detection tool** and is not a replacement for professional anti-malware software. It may miss sophisticated attacks and should be used as part of a broader security strategy.

## Features

- Monitors directories for suspicious file activities
- Detects rapid file modifications/creations
- Identifies known ransomware file extensions
- Recognizes potential ransom note creation
- Alerts on high file I/O operations in a short time period

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Installation

1. Download the script:
**⬇[Download Basic ransomware activity detection(.py)](https://github.com/Sree-Ajitha/Python-Security-Tools/blob/34eb354ae0b63f495949bffb9461532540552711/ransomware_detector.py)**

Where:
- `-t` or `--threshold` is the number of file operations that will trigger an alert
- `-w` or `--window` is the time window in seconds to monitor

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `-d, --directories` | Directories to monitor (space separated) |
| `-t, --threshold` | Alert threshold for file operations (default: 50) |
| `-w, --window` | Time window in seconds to monitor for activity (default: 10) |

## How It Works

1. The script first establishes a baseline by scanning and hashing files in monitored directories
2. It continuously checks for new or modified files
3. It analyzes file modifications for suspicious patterns:
   - High number of file changes in a short period
   - Files with known ransomware extensions
   - Creation of potential ransom notes
4. When suspicious activity is detected, it logs warnings and suggests actions to take

## Limitations

- High CPU/disk usage during initial scan of large directories
- May generate false positives during normal high file activity (installations, updates)
- Only detects active ransomware; cannot prevent or remove infections
- Limited to monitoring the file system, not other attack vectors

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.