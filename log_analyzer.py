#!/usr/bin/env python3
"""
Log Parser and Suspicious IP Detection Tool

This script parses log files, extracts IP addresses, and identifies potentially 
suspicious activities based on multiple detection criteria.
"""

import re
import sys
import argparse
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime
import json
import csv
import os
from typing import Dict, List, Set, Any, Optional, Union


class LogAnalyzer:
    """Main class for log analysis and suspicious IP detection."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the log analyzer with optional configuration."""
        # Default configuration
        self.config = {
            'threshold_requests': 100,  # Number of requests per minute to flag as suspicious
            'threshold_failed_logins': 5,  # Number of failed logins to flag as suspicious
            'sensitive_paths': ['/admin', '/login', '/wp-login', '/administrator', '/.env', '/.git'],
            'whitelist': [],
            'blacklist': [],
            'log_patterns': {
                'apache': r'(\d+\.\d+\.\d+\.\d+) - .* \[(.*?)\] "(.*?)" (\d+) .*',
                'nginx': r'(\d+\.\d+\.\d+\.\d+) - .* \[(.*?)\] "(.*?)" (\d+) .*',
                'auth': r'(?:Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)'
            }
        }

        # Override defaults with provided configuration
        if config:
            self.config.update(config)

        # Initialize data structures
        self.ip_request_count = defaultdict(int)
        self.ip_failed_logins = defaultdict(int)
        self.ip_sensitive_access = defaultdict(list)
        self.ip_status_codes = defaultdict(Counter)
        self.ip_user_agents = defaultdict(set)
        self.ip_timestamps = defaultdict(list)
        self.ip_countries = {}  # Will be populated if geo lookup is available

    def parse_log_file(self, file_path: str, log_type: str = 'apache') -> None:
        """Parse a log file and extract information."""
        try:
            pattern = self.config['log_patterns'].get(log_type)
            if not pattern:
                raise ValueError(f"Unsupported log type: {log_type}")

            ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
            log_regex = re.compile(pattern)

            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    if log_type in ('apache', 'nginx'):
                        self._parse_web_log(line, log_regex)
                    elif log_type == 'auth':
                        self._parse_auth_log(line, log_regex)
                    else:
                        # Generic IP extraction
                        ip_match = ip_pattern.search(line)
                        if ip_match:
                            ip = ip_match.group(0)
                            if self._is_valid_ip(ip):
                                self.ip_request_count[ip] += 1

            print(f"Processed {file_path} as {log_type} log")
        except Exception as e:
            print(f"Error processing {file_path}: {e}", file=sys.stderr)

    def parse_stdin(self, log_type: str = 'apache') -> None:
        """Parse log data from standard input."""
        try:
            pattern = self.config['log_patterns'].get(log_type)
            if not pattern:
                raise ValueError(f"Unsupported log type: {log_type}")

            ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
            log_regex = re.compile(pattern)

            print("Reading from standard input (Ctrl+D or Ctrl+Z to end)...")
            line_count = 0

            for line in sys.stdin:
                line_count += 1
                if log_type in ('apache', 'nginx'):
                    self._parse_web_log(line, log_regex)
                elif log_type == 'auth':
                    self._parse_auth_log(line, log_regex)
                else:
                    # Generic IP extraction
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        ip = ip_match.group(0)
                        if self._is_valid_ip(ip):
                            self.ip_request_count[ip] += 1

            print(f"Processed {line_count} lines from stdin as {log_type} log")
        except Exception as e:
            print(f"Error processing stdin: {e}", file=sys.stderr)

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid and not in whitelist."""
        if ip in self.config['whitelist']:
            return False

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _parse_web_log(self, line: str, regex: re.Pattern) -> None:
        """Parse a web server log entry."""
        match = regex.search(line)
        if not match:
            return

        ip, timestamp_str, request, status_code = match.groups()

        # Skip whitelisted IPs
        if not self._is_valid_ip(ip):
            return

        # Count the request
        self.ip_request_count[ip] += 1

        # Store the timestamp
        try:
            timestamp = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            self.ip_timestamps[ip].append(timestamp)
        except:
            pass  # Skip timestamp if parsing fails

        # Check for sensitive path access
        for path in self.config['sensitive_paths']:
            if path in request:
                self.ip_sensitive_access[ip].append((path, request))

        # Store status code
        try:
            self.ip_status_codes[ip][int(status_code)] += 1
        except:
            pass

        # Extract user agent if available
        ua_match = re.search(r'"([^"]*)"$', line)
        if ua_match:
            self.ip_user_agents[ip].add(ua_match.group(1))

    def _parse_auth_log(self, line: str, regex: re.Pattern) -> None:
        """Parse an authentication log entry."""
        match = regex.search(line)
        if not match:
            return

        ip = match.group(1)

        # Skip whitelisted IPs
        if not self._is_valid_ip(ip):
            return

        # Count failed login attempts
        self.ip_failed_logins[ip] += 1

    def detect_suspicious_ips(self) -> Dict[str, List[str]]:
        """Analyze the collected data and return suspicious IPs with reasons."""
        suspicious_ips = {}

        # Check blacklisted IPs
        for ip in self.ip_request_count:
            if ip in self.config['blacklist']:
                suspicious_ips[ip] = suspicious_ips.get(ip, []) + ["Blacklisted IP"]

        # Check for high request rates
        for ip, count in self.ip_request_count.items():
            if count > self.config['threshold_requests']:
                suspicious_ips[ip] = suspicious_ips.get(ip, []) + [f"High request volume: {count} requests"]

        # Check for failed login attempts
        for ip, count in self.ip_failed_logins.items():
            if count > self.config['threshold_failed_logins']:
                suspicious_ips[ip] = suspicious_ips.get(ip, []) + [f"Multiple failed logins: {count} attempts"]

        # Check for sensitive path access
        for ip, accesses in self.ip_sensitive_access.items():
            if len(accesses) > 0:
                paths = ', '.join(set(path for path, _ in accesses[:5]))  # Show at most 5 different paths
                suspicious_ips[ip] = suspicious_ips.get(ip, []) + [f"Accessed sensitive paths: {paths}"]

        # Check for error responses
        for ip, status_counts in self.ip_status_codes.items():
            error_count = sum(status_counts[code] for code in range(400, 500))
            if error_count > 10:
                suspicious_ips[ip] = suspicious_ips.get(ip, []) + [f"Multiple 4xx errors: {error_count} responses"]

        return suspicious_ips

    def analyze_request_patterns(self, suspicious_ips: Dict[str, List[str]]) -> None:
        """Analyze temporal patterns for suspicious IPs."""
        for ip in list(suspicious_ips.keys()):
            timestamps = self.ip_timestamps.get(ip, [])
            if len(timestamps) < 5:
                continue

            # Check for evenly spaced requests (potential bot)
            timestamps.sort()
            intervals = [(timestamps[i + 1] - timestamps[i]).total_seconds()
                         for i in range(len(timestamps) - 1)]

            if len(intervals) >= 5:
                # Calculate standard deviation of intervals
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                std_dev = variance ** 0.5

                # If std_dev is very low compared to mean, requests are suspiciously regular
                if mean_interval > 0 and std_dev / mean_interval < 0.1:
                    suspicious_ips[ip].append(f"Suspiciously regular request pattern (potential bot)")

    def generate_report(self, suspicious_ips: Dict[str, List[str]], output_format: str = 'text',
                        output_file: Optional[str] = None) -> None:
        """Generate a report of suspicious IPs in the specified format."""
        if not suspicious_ips:
            print("No suspicious IPs detected.")
            return

        if output_format == 'text':
            report = self._generate_text_report(suspicious_ips)
        elif output_format == 'json':
            report = self._generate_json_report(suspicious_ips)
        elif output_format == 'csv':
            report = self._generate_csv_report(suspicious_ips)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Report saved to {output_file}")
        else:
            print(report)

    def _generate_text_report(self, suspicious_ips: Dict[str, List[str]]) -> str:
        """Generate a text report."""
        report = ["=== Suspicious IP Activity Report ==="]
        report.append(f"Generated at: {datetime.now().isoformat()}")
        report.append(f"Total suspicious IPs: {len(suspicious_ips)}")
        report.append("")

        for i, (ip, reasons) in enumerate(suspicious_ips.items(), 1):
            report.append(f"{i}. {ip}")
            for reason in reasons:
                report.append(f"   - {reason}")

            # Add request count if available
            if ip in self.ip_request_count:
                report.append(f"   - Total requests: {self.ip_request_count[ip]}")

            # Add status code breakdown if available
            if ip in self.ip_status_codes and self.ip_status_codes[ip]:
                status_str = ", ".join(f"{code}: {count}" for code, count in
                                       sorted(self.ip_status_codes[ip].items()))
                report.append(f"   - Status codes: {status_str}")

            report.append("")

        return "\n".join(report)

    def _generate_json_report(self, suspicious_ips: Dict[str, List[str]]) -> str:
        """Generate a JSON report."""
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_suspicious_ips": len(suspicious_ips),
            "ips": {}
        }

        for ip, reasons in suspicious_ips.items():
            ip_data = {
                "reasons": reasons,
                "request_count": self.ip_request_count.get(ip, 0),
                "status_codes": dict(self.ip_status_codes.get(ip, {})),
                "user_agents": list(self.ip_user_agents.get(ip, set())),
                "sensitive_paths_accessed": [req for path, req in self.ip_sensitive_access.get(ip, [])]
            }
            report_data["ips"][ip] = ip_data

        return json.dumps(report_data, indent=2)

    def _generate_csv_report(self, suspicious_ips: Dict[str, List[str]]) -> str:
        """Generate a CSV report."""
        rows = [["IP", "Reasons", "Request Count", "Status Codes", "User Agents"]]

        for ip, reasons in suspicious_ips.items():
            rows.append([
                ip,
                "; ".join(reasons),
                str(self.ip_request_count.get(ip, 0)),
                str(dict(self.ip_status_codes.get(ip, {}))),
                "; ".join(list(self.ip_user_agents.get(ip, set())))
            ])

        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(rows)
        return output.getvalue()


def interactive_mode() -> dict:
    """Interactive mode to collect parameters from the user."""
    print("=== Log Analyzer Interactive Mode ===")

    # Ask for log file path
    while True:
        log_file = input("Enter log file path (or 'stdin' to read from standard input): ")
        if log_file.lower() == 'stdin':
            log_file = None
            break
        if os.path.exists(log_file):
            break
        print(f"Error: File '{log_file}' not found. Please try again.")

    # Ask for log type
    log_types = ['apache', 'nginx', 'auth', 'generic']
    print("\nAvailable log types:")
    for i, lt in enumerate(log_types, 1):
        print(f"{i}. {lt}")

    while True:
        try:
            type_choice = int(input("Choose log type (1-4): "))
            if 1 <= type_choice <= 4:
                log_type = log_types[type_choice - 1]
                break
            print("Invalid choice. Please enter a number between 1 and 4.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Ask for output format
    formats = ['text', 'json', 'csv']
    print("\nOutput formats:")
    for i, fmt in enumerate(formats, 1):
        print(f"{i}. {fmt}")

    while True:
        try:
            format_choice = int(input("Choose output format (1-3): "))
            if 1 <= format_choice <= 3:
                output_format = formats[format_choice - 1]
                break
            print("Invalid choice. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Ask for output file
    output_file = input("\nOutput file (leave empty for console output): ")
    if output_file.strip() == '':
        output_file = None

    # Thresholds
    try:
        threshold_requests = int(input("\nRequest threshold for suspicious activity (default: 100): ") or "100")
    except ValueError:
        print("Invalid input. Using default value of 100.")
        threshold_requests = 100

    try:
        threshold_logins = int(input("Failed login threshold for suspicious activity (default: 5): ") or "5")
    except ValueError:
        print("Invalid input. Using default value of 5.")
        threshold_logins = 5

    # Whitelist and blacklist
    whitelist = input("\nWhitelisted IPs (comma-separated, leave empty for none): ")
    blacklist = input("Blacklisted IPs (comma-separated, leave empty for none): ")

    # Return parameters as a dictionary
    return {
        'log_file': log_file,
        'log_type': log_type,
        'output_format': output_format,
        'output_file': output_file,
        'threshold_requests': threshold_requests,
        'threshold_logins': threshold_logins,
        'whitelist': whitelist.split(',') if whitelist else [],
        'blacklist': blacklist.split(',') if blacklist else []
    }


def main() -> None:
    """Main function to run the script."""
    # Check if any arguments were provided
    if len(sys.argv) == 1:
        # No arguments - show a more helpful message and offer interactive mode
        print("No arguments provided.\n")
        print("Run with --help for usage information, or use interactive mode.")

        while True:
            choice = input("\nWould you like to run in interactive mode? (y/n): ")
            if choice.lower() in ('y', 'yes'):
                params = interactive_mode()
                break
            elif choice.lower() in ('n', 'no'):
                print("\nExiting. Run with --help to see usage information.")
                return
            else:
                print("Invalid choice. Please enter 'y' or 'n'.")

    else:
        # Arguments provided - use argparse
        parser = argparse.ArgumentParser(
            description="Parse logs and detect suspicious IP addresses.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('--log-file', '-f',
                            help='Log file to analyze (use "stdin" to read from standard input)')
        parser.add_argument('--log-type', '-t', default='apache',
                            choices=['apache', 'nginx', 'auth', 'generic'],
                            help='Type of log file')
        parser.add_argument('--output', '-o', help='Output file for the report')
        parser.add_argument('--format', default='text', choices=['text', 'json', 'csv'],
                            help='Output format for the report')
        parser.add_argument('--threshold-requests', type=int, default=100,
                            help='Request threshold for suspicious activity')
        parser.add_argument('--threshold-logins', type=int, default=5,
                            help='Failed login threshold for suspicious activity')
        parser.add_argument('--whitelist', help='Comma-separated list of whitelisted IPs')
        parser.add_argument('--blacklist', help='Comma-separated list of blacklisted IPs')
        parser.add_argument('--sensitive-paths', help='Comma-separated list of additional sensitive paths')

        args = parser.parse_args()

        # Convert arguments to parameter dictionary
        params = {
            'log_file': args.log_file,
            'log_type': args.log_type,
            'output_format': args.format,
            'output_file': args.output,
            'threshold_requests': args.threshold_requests,
            'threshold_logins': args.threshold_logins,
            'whitelist': args.whitelist.split(',') if args.whitelist else [],
            'blacklist': args.blacklist.split(',') if args.blacklist else []
        }

    # Prepare configuration
    config = {
        'threshold_requests': params['threshold_requests'],
        'threshold_failed_logins': params['threshold_logins'],
        'whitelist': params['whitelist'],
        'blacklist': params['blacklist'],
    }

    # Initialize analyzer with configuration
    analyzer = LogAnalyzer(config)

    # Parse log file or stdin
    if params['log_file'] is None or params['log_file'].lower() == 'stdin':
        analyzer.parse_stdin(params['log_type'])
    else:
        analyzer.parse_log_file(params['log_file'], params['log_type'])

    # Detect suspicious IPs
    suspicious_ips = analyzer.detect_suspicious_ips()

    # Analyze request patterns
    analyzer.analyze_request_patterns(suspicious_ips)

    # Generate and output the report
    analyzer.generate_report(suspicious_ips, params['output_format'], params['output_file'])


if __name__ == '__main__':
    main()