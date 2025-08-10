# Cross-Platform Brute Force Login Monitor

A Python utility that monitors authentication logs to detect and respond to potential brute force login attempts across Linux and Windows systems.

## Features

- **Cross-Platform Support**: Works on Linux (Ubuntu, Debian, CentOS, RHEL) and Windows
- **Automatic OS Detection**: Detects your operating system and uses the appropriate log sources
- **Real-time Monitoring**: Continuously watches for login failure events
- **IP-based Tracking**: Tracks failed login attempts by IP address
- **Configurable Thresholds**: Set custom time windows and attempt thresholds
- **Automatic Blocking**: Optional blocking of suspicious IPs via iptables or Windows Firewall
- **Email Alerts**: Notification when suspicious activity is detected
- **IP Whitelisting**: Exclude trusted IPs from monitoring

## Requirements

- Python 3.6+
- For Windows: `pywin32` module (`pip install pywin32`)
- Administrative privileges (for accessing log files and blocking IPs)

## Installation

1. Clone this repository or **⬇[Download Brute force login monitoring(.py)](https://github.com/Sree-Ajitha/Python-Security-Tools/blob/95e6609993ca159ab03f734aedd10beae8166aeb/brute_force_monitor_Version2.py)**
2. Install required dependencies:

```bash
# For Windows systems
pip install pywin32

# No additional dependencies for Linux
```

3. Make the script executable (Linux only):

```bash
chmod +x brute_force_monitor.py
```

## Usage

### Basic Usage

```bash
# Linux (needs sudo for log access)
sudo python3 brute_force_monitor.py

# Windows (run as administrator)
python brute_force_monitor.py
```

This will automatically detect your OS and monitor the appropriate authentication logs with default settings (5 failed attempts within 300 seconds).

### Advanced Usage

```bash
# Linux example with custom settings
sudo python3 brute_force_monitor.py --threshold 3 --time-window 600 --block --email admin@example.com --whitelist 192.168.1.10 10.0.0.5

# Windows example with explicit OS selection
python brute_force_monitor.py --os windows --threshold 3 --time-window 600 --block
```

### Command Line Options

- `--log-file`: Path to the authentication log file (auto-detected if not specified)
- `--os`: Operating system type (`windows`, `ubuntu`, `centos`, or `auto`)
- `--threshold`: Number of failed attempts before triggering an alert (default: 5)
- `--time-window`: Time window in seconds to track attempts (default: 300)
- `--block`: Enable automatic blocking of suspicious IPs 
- `--email`: Email address to send alerts to
- `--whitelist`: Space-separated list of IPs that should not trigger alerts

## Log Files by OS

The script automatically detects and uses the appropriate log file based on your OS:

- **Ubuntu/Debian**: `/var/log/auth.log`
- **CentOS/RHEL/Fedora**: `/var/log/secure`
- **Windows**: Windows Event Log (Security)

## Running as a Service

### Linux (using Systemd)

1. Create a service file:

```bash
sudo nano /etc/systemd/system/brute-force-monitor.service
```

2. Add the following content:

```ini
[Unit]
Description=Brute Force Login Attempt Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/brute_force_monitor.py --threshold 5 --time-window 300
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable brute-force-monitor
sudo systemctl start brute-force-monitor
```

### Windows (using NSSM)

1. Download and install NSSM (Non-Sucking Service Manager)
2. Open an administrator command prompt
3. Run:

```
nssm install BruteForceMonitor
```

4. In the GUI that appears:
   - Set the path to your Python executable
   - Set arguments to the full path of your script
   - Configure other service options as needed
   - Click "Install service"

## Email Notifications

For email notifications to work, you need to configure an SMTP server. Edit the `send_alert` method with your SMTP server details.

## Security Notes

- This script requires administrative privileges to access log files and block IPs
- On Windows, the script needs to be run as Administrator
- On Linux, the script needs sudo access for log files and iptables
- Consider the implications of automated IP blocking in your environment

## License

[MIT License](LICENSE)