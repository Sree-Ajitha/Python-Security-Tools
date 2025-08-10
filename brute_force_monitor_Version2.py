#!/usr/bin/env python3
"""
Cross-Platform Brute Force Login Attempt Monitor

This script monitors authentication logs for potential brute force attacks
by tracking failed login attempts from IP addresses and sending alerts
when suspicious activity is detected.

Supports Linux (Ubuntu, Debian, CentOS, RHEL) and Windows systems.
"""

import re
import time
import smtplib
import argparse
import subprocess
import logging
import platform
import os
import signal
import sys
from datetime import datetime
from collections import defaultdict
from email.message import EmailMessage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('brute_force_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Detect if running on Windows
IS_WINDOWS = platform.system() == 'Windows'

# Import Windows-specific modules if on Windows
if IS_WINDOWS:
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import winerror
    except ImportError:
        logger.error("Windows modules not found. Please install pywin32: pip install pywin32")
        sys.exit(1)

class BruteForceMonitor:
    def __init__(self, log_file=None, os_type=None, threshold=5, time_window=300, 
                 block_ips=False, notification_email=None, whitelist=None):
        """
        Initialize the brute force monitor.
        
        Args:
            log_file (str): Path to the authentication log file to monitor (auto-detected if None)
            os_type (str): Operating system type ('windows', 'ubuntu', 'centos', etc.)
            threshold (int): Number of failed attempts before triggering an alert
            time_window (int): Time window in seconds to track attempts
            block_ips (bool): Whether to block IPs that exceed the threshold
            notification_email (str): Email to send alerts to
            whitelist (list): List of IPs that should not trigger alerts
        """
        self.threshold = threshold
        self.time_window = time_window
        self.block_ips = block_ips
        self.notification_email = notification_email
        self.whitelist = whitelist or []
        self.os_type = os_type or self._detect_os()
        self.log_file = log_file or self._get_default_log_file()
        
        # Track failed attempts with timestamps
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()
        
        # Configure OS-specific settings
        self._configure_os_settings()
    
    def _detect_os(self):
        """Detect the operating system."""
        system = platform.system().lower()
        if system == 'linux':
            distro = ''
            try:
                # Try to get Linux distribution
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('ID='):
                                distro = line.split('=')[1].strip().strip('"').lower()
                                break
            except:
                pass
            
            if distro in ('ubuntu', 'debian', 'pop', 'mint'):
                return 'ubuntu'
            elif distro in ('centos', 'rhel', 'fedora', 'amzn'):
                return 'centos'
            return 'linux'
        elif system == 'windows':
            return 'windows'
        else:
            return system
    
    def _get_default_log_file(self):
        """Get default log file based on OS."""
        if self.os_type == 'ubuntu':
            return '/var/log/auth.log'
        elif self.os_type == 'centos':
            return '/var/log/secure'
        elif self.os_type == 'windows':
            return 'Security'  # Windows event log name
        else:
            # Default fallback
            candidates = ['/var/log/auth.log', '/var/log/secure']
            for candidate in candidates:
                if os.path.exists(candidate):
                    return candidate
            return '/var/log/auth.log'  # Default fallback
    
    def _configure_os_settings(self):
        """Configure OS-specific settings like regex patterns."""
        # Configure regex patterns for different OS types
        if self.os_type in ('ubuntu', 'centos', 'linux'):
            self.patterns = [
                # SSH failed login pattern
                re.compile(r'.*sshd\[\d+\]: Failed password for .* from (\d+\.\d+\.\d+\.\d+) port \d+'),
                # Invalid user pattern
                re.compile(r'.*sshd\[\d+\]: Invalid user .* from (\d+\.\d+\.\d+\.\d+)'),
                # Failed authentication pattern
                re.compile(r'.*authentication failure.* rhost=(\d+\.\d+\.\d+\.\d+)'),
            ]
            self.monitor_func = self._monitor_linux
        elif self.os_type == 'windows':
            # No regex patterns needed for Windows - we'll parse event data directly
            self.patterns = []
            self.monitor_func = self._monitor_windows
            # For Windows, we'll track the last event timestamp
            self.last_event_time = datetime.now()
        else:
            logger.error(f"Unsupported OS type: {self.os_type}")
            sys.exit(1)
    
    def is_whitelisted(self, ip):
        """Check if an IP is in the whitelist."""
        return ip in self.whitelist
    
    def detect_failed_attempt(self, line):
        """
        Check if a log line contains a failed login attempt.
        
        Args:
            line (str): Log line to check
        
        Returns:
            str or None: The IP address if found, None otherwise
        """
        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                return match.group(1)
        return None
    
    def check_threshold(self, ip, current_time):
        """
        Check if an IP has exceeded the threshold of failed attempts.
        
        Args:
            ip (str): IP address to check
            current_time (float): Current timestamp
            
        Returns:
            bool: True if threshold exceeded, False otherwise
        """
        # Filter attempts within time window
        recent_attempts = [
            t for t in self.failed_attempts[ip] 
            if current_time - t < self.time_window
        ]
        
        # Update the attempts list to only include recent attempts
        self.failed_attempts[ip] = recent_attempts
        
        # Check if the number of recent attempts exceeds the threshold
        return len(recent_attempts) >= self.threshold
    
    def block_ip(self, ip):
        """
        Block an IP using iptables (Linux) or Windows Firewall.
        
        Args:
            ip (str): IP address to block
        """
        if ip in self.blocked_ips:
            return
            
        try:
            if self.os_type in ('ubuntu', 'centos', 'linux'):
                # Use iptables to block the IP on Linux
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
                self.blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
            elif self.os_type == 'windows':
                # Use Windows Firewall to block the IP
                rule_name = f"BruteForceBlock_{ip}"
                cmd = (f'powershell -Command "New-NetFirewallRule -DisplayName \'{rule_name}\' '
                       f'-Direction Inbound -Action Block -RemoteAddress {ip}"')
                subprocess.run(cmd, shell=True, check=True)
                self.blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e}")
    
    def send_alert(self, ip, attempts):
        """
        Send an email alert about a potential brute force attack.
        
        Args:
            ip (str): IP address that triggered the alert
            attempts (int): Number of failed attempts
        """
        if not self.notification_email:
            return
            
        try:
            msg = EmailMessage()
            msg.set_content(f"""
            Potential brute force attack detected:
            
            IP: {ip}
            Failed attempts: {attempts}
            Time window: {self.time_window} seconds
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            OS: {self.os_type}
            
            This alert was generated by the brute force monitoring script.
            """)
            
            msg['Subject'] = f'ALERT: Potential brute force attack from {ip}'
            msg['From'] = 'security@yourdomain.com'
            msg['To'] = self.notification_email
            
            # This requires proper SMTP configuration in a production environment
            # For simplicity, we're just logging the alert
            logger.info(f"Would send email alert for IP {ip} with {attempts} attempts")
            # Uncomment to actually send email:
            # with smtplib.SMTP('localhost') as s:
            #     s.send_message(msg)
            
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
    
    def _monitor_linux(self):
        """
        Start monitoring the log file for brute force attempts on Linux.
        """
        logger.info(f"Starting brute force monitor on Linux log file: {self.log_file}")
        
        try:
            # Check if log file exists
            if not os.path.exists(self.log_file):
                logger.error(f"Log file does not exist: {self.log_file}")
                return
                
            with open(self.log_file, 'r') as f:
                # Move to the end of the file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if not line:
                        # No new lines, wait a bit
                        time.sleep(0.1)
                        continue
                    
                    # Check for failed login attempts
                    ip = self.detect_failed_attempt(line)
                    if ip and not self.is_whitelisted(ip):
                        current_time = time.time()
                        self.failed_attempts[ip].append(current_time)
                        
                        if self.check_threshold(ip, current_time):
                            attempts = len(self.failed_attempts[ip])
                            logger.warning(f"Potential brute force attack from {ip} with {attempts} attempts")
                            
                            # Send alert
                            self.send_alert(ip, attempts)
                            
                            # Block IP if enabled
                            if self.block_ips:
                                self.block_ip(ip)
                                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
    
    def _extract_ip_from_windows_event(self, event):
        """Extract IP address from Windows event data."""
        try:
            # Different event IDs have different data structures
            # Event ID 4625 is a failed login attempt
            if event.EventID == 4625:
                # Parse the event data
                for data in event.StringInserts:
                    # IP address is typically in formats like:
                    # - Source Network Address: 192.168.1.1
                    # - Workstation Name: 192.168.1.1
                    if re.match(r'\d+\.\d+\.\d+\.\d+', data):
                        return data
            return None
        except Exception as e:
            logger.error(f"Error extracting IP from Windows event: {e}")
            return None
    
    def _monitor_windows(self):
        """
        Start monitoring the Windows Event Log for brute force attempts.
        """
        logger.info(f"Starting brute force monitor on Windows Event Log: {self.log_file}")
        
        try:
            # Define event types to monitor (failed logins)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                # Open the event log
                hand = win32evtlog.OpenEventLog(None, self.log_file)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                win32evtlog.CloseEventLog(hand)
                
                current_time = time.time()
                
                for event in events:
                    # Skip older events we've already processed
                    event_time = datetime.fromtimestamp(int(event.TimeGenerated))
                    if event_time <= self.last_event_time:
                        continue
                    
                    # Failed login events (4625 is the Event ID for failed logins)
                    if event.EventID == 4625:
                        ip = self._extract_ip_from_windows_event(event)
                        
                        if ip and not self.is_whitelisted(ip):
                            self.failed_attempts[ip].append(current_time)
                            
                            if self.check_threshold(ip, current_time):
                                attempts = len(self.failed_attempts[ip])
                                logger.warning(f"Potential brute force attack from {ip} with {attempts} attempts")
                                
                                # Send alert
                                self.send_alert(ip, attempts)
                                
                                # Block IP if enabled
                                if self.block_ips:
                                    self.block_ip(ip)
                
                # Update the last event time
                self.last_event_time = datetime.now()
                
                # Wait before checking again
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
        except Exception as e:
            logger.error(f"Error during Windows event monitoring: {e}")
    
    def monitor(self):
        """Start monitoring based on the detected OS."""
        logger.info(f"Starting brute force monitor on {self.os_type}")
        logger.info(f"Threshold: {self.threshold} attempts within {self.time_window} seconds")
        
        # Use the appropriate monitoring function based on OS
        self.monitor_func()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Cross-platform monitor for brute force login attempts')
    parser.add_argument('--log-file', type=str,
                        help='Log file to monitor (auto-detected if not specified)')
    parser.add_argument('--os', type=str, choices=['windows', 'ubuntu', 'centos', 'auto'],
                        default='auto', help='Operating system type (auto-detected if not specified)')
    parser.add_argument('--threshold', type=int, default=5,
                        help='Number of failed attempts before alert (default: 5)')
    parser.add_argument('--time-window', type=int, default=300,
                        help='Time window in seconds for tracking attempts (default: 300)')
    parser.add_argument('--block', action='store_true',
                        help='Block IPs that exceed the threshold using iptables/Windows Firewall')
    parser.add_argument('--email', type=str,
                        help='Email address to send alerts to')
    parser.add_argument('--whitelist', type=str, nargs='+',
                        help='IPs to whitelist (space separated)')
    
    args = parser.parse_args()
    
    # Handle "auto" OS setting
    if args.os == 'auto':
        args.os = None
    
    return args

def signal_handler(sig, frame):
    """Handle Ctrl+C to exit gracefully."""
    logger.info("Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_arguments()
    
    # Create and start the monitor
    monitor = BruteForceMonitor(
        log_file=args.log_file,
        os_type=args.os,
        threshold=args.threshold,
        time_window=args.time_window,
        block_ips=args.block,
        notification_email=args.email,
        whitelist=args.whitelist
    )
    
    monitor.monitor()