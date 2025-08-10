#!/usr/bin/env python3
"""
Basic Ransomware Activity Detection Script
-----------------------------------------
This script monitors file system activities to detect potential ransomware behavior.
It alerts on suspicious patterns such as:
- Rapid file modifications/creations
- Known ransomware file extensions
- Ransom note creation
- High file I/O operations in a short time period
"""

import os
import time
import logging
import hashlib
import re
import argparse
import platform
from datetime import datetime
from collections import deque, Counter

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ransomware_detector.log"),
        logging.StreamHandler()
    ]
)

class RansomwareDetector:
    def __init__(self, directories_to_monitor, alert_threshold=50, time_window=10):
        """
        Initialize the ransomware detector.
        
        Args:
            directories_to_monitor (list): List of directories to monitor
            alert_threshold (int): Number of file operations in time_window to trigger alert
            time_window (int): Time window in seconds to monitor file operations
        """
        self.directories = directories_to_monitor
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        
        # Store recent file operations for analysis
        self.recent_operations = deque(maxlen=1000)
        
        # Known ransomware extensions
        self.suspicious_extensions = [
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".ransomware", 
            ".crypted", ".cerber", ".locky", ".wannacry", ".wcry", ".tesla",
            ".zepto", ".thor", ".aesir", ".alcatraz", ".dharma", ".wallet",
            ".osiris", ".cryptolocker", ".crime", ".crime", ".vault"
        ]
        
        # Common ransom note patterns
        self.ransom_note_patterns = [
            r"how.*decrypt", r"ransom", r"bitcoin", r"payment", r"recover.*files",
            r"your.*files.*encrypted", r"pay", r"btc", r"decrypt.*key", r"restore.*files",
            r"README.*txt", r"DECRYPT.*txt", r"HOW.*TO.*DECRYPT.*", r"HELP.*DECRYPT"
        ]
        
        self.file_hashes = {}  # To track file changes
        logging.info("Ransomware detector initialized")
        logging.info(f"Monitoring directories: {', '.join(self.directories)}")
    
    def start_monitoring(self):
        """Start monitoring file system activities."""
        logging.info("Starting monitoring...")
        
        try:
            self._initial_scan()
            
            while True:
                for directory in self.directories:
                    self._scan_directory(directory)
                
                # Analyze recent activity
                self._analyze_activity()
                
                # Wait before next scan to reduce CPU usage
                time.sleep(2)
                
        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user")
        except Exception as e:
            logging.error(f"Error during monitoring: {str(e)}")
    
    def _initial_scan(self):
        """Perform initial scan to establish baseline."""
        logging.info("Performing initial scan...")
        
        for directory in self.directories:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            if os.path.isfile(file_path):
                                # Store file hash
                                self.file_hashes[file_path] = self._get_file_hash(file_path)
                        except Exception as e:
                            logging.debug(f"Couldn't process {file}: {str(e)}")
            else:
                logging.warning(f"Directory not found: {directory}")
        
        logging.info(f"Initial scan complete. Indexed {len(self.file_hashes)} files")
    
    def _scan_directory(self, directory):
        """
        Scan a directory for changes.
        
        Args:
            directory (str): Directory path to scan
        """
        if not os.path.exists(directory):
            return
            
        current_time = time.time()
        
        for root, _, files in os.walk(directory):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    if not os.path.isfile(file_path):
                        continue
                        
                    # Check if file is new or modified
                    current_hash = self._get_file_hash(file_path)
                    
                    if file_path not in self.file_hashes:
                        # New file
                        self.file_hashes[file_path] = current_hash
                        self._record_operation("create", file_path, current_time)
                        
                        # Check if it's a suspicious file
                        if self._is_suspicious_file(file_path):
                            logging.warning(f"Suspicious file created: {file_path}")
                    
                    elif current_hash != self.file_hashes[file_path]:
                        # File modified
                        self.file_hashes[file_path] = current_hash
                        self._record_operation("modify", file_path, current_time)
                        
                except Exception as e:
                    logging.debug(f"Error scanning {file_path}: {str(e)}")
    
    def _get_file_hash(self, file_path, read_size=4096):
        """Get a hash of the first few KB of a file (for performance)."""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read(read_size)
                return hashlib.md5(file_data).hexdigest()
        except Exception:
            # Return a random hash if we can't read the file
            return os.urandom(16).hex()
    
    def _record_operation(self, operation_type, file_path, timestamp):
        """Record a file operation for analysis."""
        self.recent_operations.append({
            'type': operation_type,
            'path': file_path,
            'timestamp': timestamp
        })
    
    def _is_suspicious_file(self, file_path):
        """Check if a file looks suspicious (ransom note or encrypted file)."""
        filename = os.path.basename(file_path).lower()
        
        # Check for suspicious extensions
        for ext in self.suspicious_extensions:
            if filename.endswith(ext):
                return True
        
        # Check for ransom note patterns in filename
        for pattern in self.ransom_note_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
                
        # Check content of small text files for ransom notes
        if os.path.getsize(file_path) < 20000 and file_path.endswith(('.txt', '.html', '.htm')):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                    for pattern in self.ransom_note_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
            except Exception:
                pass
                
        return False
    
    def _analyze_activity(self):
        """Analyze recent file operations to detect ransomware-like behavior."""
        current_time = time.time()
        # Get operations within time window
        recent_ops = [op for op in self.recent_operations 
                      if current_time - op['timestamp'] <= self.time_window]
        
        # Count operations in the time window
        op_count = len(recent_ops)
        
        # If we have a lot of operations in a short time, trigger alert
        if op_count >= self.alert_threshold:
            # Count operations by type
            op_types = Counter([op['type'] for op in recent_ops])
            
            # Count suspicious operations
            suspicious_ops = sum(1 for op in recent_ops 
                               if self._is_suspicious_file(op['path']))
            
            logging.warning(f"ALERT: High file activity detected! {op_count} operations in {self.time_window} seconds")
            logging.warning(f"Operation types: {dict(op_types)}")
            
            if suspicious_ops > 0:
                logging.critical(f"CRITICAL: {suspicious_ops} suspicious files detected! Possible ransomware attack in progress!")
                self._suggest_actions()
    
    def _suggest_actions(self):
        """Suggest actions to take when ransomware is detected."""
        logging.critical("RECOMMENDED ACTIONS:")
        logging.critical("1. Disconnect this computer from the network immediately")
        logging.critical("2. Power off affected systems if possible")
        logging.critical("3. Alert your IT security team or administrator")
        logging.critical("4. Do not pay any ransom without consulting security professionals")
        logging.critical("5. Check backups for clean versions of your files")
        
        # Platform-specific recommendations
        if platform.system() == "Windows":
            logging.critical("Windows-specific: Check Volume Shadow Copies for file recovery")
        
def get_default_directories():
    """Get default directories based on the platform."""
    system = platform.system()
    if system == "Windows":
        return [os.path.join(os.environ['USERPROFILE'], 'Documents'), 
                os.path.join(os.environ['USERPROFILE'], 'Desktop')]
    elif system == "Darwin":  # macOS
        return [os.path.join(os.path.expanduser('~'), 'Documents'),
                os.path.join(os.path.expanduser('~'), 'Desktop')]
    else:  # Linux and others
        return [os.path.join(os.path.expanduser('~'), 'Documents'),
                os.path.expanduser('~')]

def parse_arguments():
    parser = argparse.ArgumentParser(description='Ransomware activity detection script')
    parser.add_argument('-d', '--directories', nargs='+', 
                        help='Directories to monitor (space separated)')
    parser.add_argument('-t', '--threshold', type=int, default=50,
                        help='Alert threshold for file operations')
    parser.add_argument('-w', '--window', type=int, default=10,
                        help='Time window in seconds to monitor for activity')
    
    args = parser.parse_args()
    
    # Use specified directories or default ones
    if not args.directories:
        args.directories = get_default_directories()
        
    return args

if __name__ == "__main__":
    print("=" * 70)
    print(" Ransomware Activity Detection Script")
    print(" WARNING: This is a basic detection tool and may miss sophisticated attacks")
    print("=" * 70)
    
    args = parse_arguments()
    detector = RansomwareDetector(
        directories_to_monitor=args.directories,
        alert_threshold=args.threshold,
        time_window=args.window
    )
    detector.start_monitoring()