#!/usr/bin/env python3
"""
USB Traffic Analyzer for HakCheck.
Monitors USB traffic for suspicious patterns.
"""

import threading
import time
import logging
import platform
import subprocess
import re
import queue
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class USBTrafficPattern:
    """Class representing a suspicious USB traffic pattern."""
    
    def __init__(self, name, description, regex=None, keystroke_rate=None, payload_size=None, severity=5):
        self.name = name
        self.description = description
        self.regex = regex
        self.keystroke_rate = keystroke_rate  # keystrokes per second
        self.payload_size = payload_size  # minimum suspicious size in bytes
        self.severity = severity  # 1-10 scale
        
    def matches(self, traffic_data):
        """Check if traffic data matches this pattern."""
        if self.regex and not re.search(self.regex, traffic_data['raw_data']):
            return False
            
        if self.keystroke_rate and traffic_data.get('keystroke_rate', 0) < self.keystroke_rate:
            return False
            
        if self.payload_size and traffic_data.get('size', 0) < self.payload_size:
            return False
            
        return True

# Define known suspicious traffic patterns
SUSPICIOUS_PATTERNS = [
    USBTrafficPattern(
        "Rapid Keystroke Injection", 
        "Unusually high rate of keystrokes, typical of scripted attacks",
        keystroke_rate=5.0,  # More than 5 keys per second is suspicious
        severity=8
    ),
    USBTrafficPattern(
        "Script Execution Command", 
        "Commands that attempt to execute scripts or open command shells",
        regex=r'(cmd\.exe|powershell|bash|sh\s+-c|exec\s+|system\s*\(|eval\s*\(|python\s+-c)',
        severity=9
    ),
    USBTrafficPattern(
        "Large HID Payload", 
        "Unusually large HID report data that may contain malicious payloads",
        payload_size=128,  # Increased threshold to reduce false positives
        severity=6
    ),
    USBTrafficPattern(
        "Download Command", 
        "Commands that attempt to download content from the internet",
        regex=r'(wget|curl|Invoke-WebRequest|DownloadFile|Net\.WebClient|http://|https://)',
        severity=8
    ),
    USBTrafficPattern(
        "Persistence Mechanism", 
        "Commands that try to establish persistence",
        regex=r'(HKEY_|registry|reg add|crontab|/etc/init|systemctl|launchctl|StartupItems|LoginItems)',
        severity=9
    ),
    USBTrafficPattern(
        "Binary Data in HID", 
        "Binary data in HID reports that is not typical keystroke data",
        regex=r'(\\x[0-9a-f]{2}){4,}',
        severity=7
    )
]

class USBTrafficAnalyzer:
    """Class for analyzing USB traffic for suspicious patterns."""
    
    def __init__(self, alert_callback=None):
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        self.traffic_queue = queue.Queue()
        self.traffic_log = []
        self.alert_callback = alert_callback
        self.device_stats = {}  # Statistics by device
        self.system = platform.system()
        self.suspicious_patterns = SUSPICIOUS_PATTERNS
        
        # Whitelist for device IDs to ignore (automatically populates with system devices)
        self.whitelist = {
            # Common system devices that trigger false positives
            "unknown": True,  # Unknown device IDs are usually internal system components
            "00000000": True,
            "01000000": True,
            "02000000": True,
            "root_hub": True,
            # Apple-specific devices
            "05ac:8005": True,  # Apple Internal Keyboard
            "05ac:026e": True,  # Apple Billboard device
        }
        
    def start(self, target_device=None):
        """Start USB traffic monitoring."""
        if self.running:
            return False
            
        self.running = True
        self.target_device = target_device  # Can be None to monitor all
        
        # Start capture thread based on the platform
        self.capture_thread = threading.Thread(
            target=self._capture_traffic,
            daemon=True
        )
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(
            target=self._analyze_traffic,
            daemon=True
        )
        self.analysis_thread.start()
        
        logger.info("USB traffic analyzer started")
        return True
        
    def stop(self):
        """Stop USB traffic monitoring."""
        if not self.running:
            return False
            
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
            
        if self.analysis_thread:
            self.analysis_thread.join(timeout=1.0)
            
        logger.info("USB traffic analyzer stopped")
        return True
        
    def get_stats(self):
        """Get traffic statistics."""
        return {
            "total_traffic": len(self.traffic_log),
            "suspicious_events": sum(1 for t in self.traffic_log if t.get('suspicious', False)),
            "device_stats": self.device_stats,
            "active": self.running
        }
        
    def get_suspicious_events(self):
        """Get a list of suspicious traffic events."""
        return [t for t in self.traffic_log if t.get('suspicious', False)]
        
    def _capture_traffic(self):
        """Platform-specific USB traffic capture."""
        if self.system == "Linux":
            self._capture_linux()
        elif self.system == "Darwin":  # macOS
            self._capture_macos()
        elif self.system == "Windows":
            self._capture_windows()
        else:
            logger.warning(f"USB traffic capture not supported on {self.system}")
            
    def _process_captured_data(self, data, device_id="unknown", timestamp=None):
        """Process and queue captured USB traffic data."""
        if not timestamp:
            timestamp = datetime.now().isoformat()
            
        # Extract more detailed device info if possible
        device_name = "Unknown Device"
        device_type = "Unknown"
        
        # Try to extract more information from the data
        if isinstance(data, str):
            # Try to find a device name in the data
            name_match = re.search(r'Product.*?["\']([^"\']+)["\']', data, re.IGNORECASE)
            if name_match:
                device_name = name_match.group(1)
                
            # Try to determine if it's a system device
            is_system = any(x in data.lower() for x in ['apple', 'root_hub', 'builtin', 'system', 'controller'])
            if is_system:
                device_type = "System Device"
                
            # Try to extract VID/PID
            vid_pid_match = re.search(r'VID[\s_=]([0-9a-fA-F]{4}).*?PID[\s_=]([0-9a-fA-F]{4})', data, re.IGNORECASE)
            if vid_pid_match:
                vid = vid_pid_match.group(1)
                pid = vid_pid_match.group(2)
                device_id = f"{vid}:{pid}"
        
        traffic_data = {
            "timestamp": timestamp,
            "device_id": device_id,
            "device_name": device_name,
            "device_type": device_type,
            "raw_data": data,
            "size": len(data),
            "suspicious": False,
            "matches": [],
            "is_system": device_type == "System Device"
        }
        
        # Count HID reports that look like keystrokes
        if 'HID' in data and re.search(r'report', data, re.IGNORECASE):
            # Count keystrokes for keystroke rate calculation
            traffic_data['keystroke_count'] = len(re.findall(r'usage\s+\([0-9a-fx]+\)', data, re.IGNORECASE))
            
            # Update device stats for this device
            if device_id not in self.device_stats:
                self.device_stats[device_id] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "total_traffic": 0,
                    "keystroke_count": 0,
                    "suspicious_count": 0
                }
            
            self.device_stats[device_id]["last_seen"] = timestamp
            self.device_stats[device_id]["total_traffic"] += 1
            self.device_stats[device_id]["keystroke_count"] += traffic_data.get('keystroke_count', 0)
            
            # Calculate keystroke rate based on time window
            try:
                first_seen = datetime.fromisoformat(self.device_stats[device_id]["first_seen"])
                last_seen = datetime.fromisoformat(self.device_stats[device_id]["last_seen"])
                time_window = (last_seen - first_seen).total_seconds()
                if time_window > 0:
                    traffic_data['keystroke_rate'] = self.device_stats[device_id]["keystroke_count"] / time_window
            except:
                pass
        
        # Add to the queue for analysis
        self.traffic_queue.put(traffic_data)
    
    def _capture_linux(self):
        """Capture USB traffic on Linux using usbmon."""
        try:
            # Check if usbmon is available
            subprocess.run(["modprobe", "usbmon"], check=True)
            
            # Determine which usbmon interface to use
            result = subprocess.run(["ls", "/sys/kernel/debug/usb/usbmon"], 
                                   capture_output=True, text=True, check=True)
            monitors = result.stdout.strip().split('\n')
            
            if not monitors:
                logger.error("No usbmon interfaces found")
                return
                
            # Use the first monitor (usually usbmon0 for all devices)
            monitor = monitors[0]
            
            # Start capture process
            cmd = ["cat", f"/sys/kernel/debug/usb/usbmon/{monitor}"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            
            # Read and process output
            while self.running:
                line = process.stdout.readline().strip()
                if not line:
                    continue
                    
                # Extract device ID from usbmon output
                device_match = re.search(r'S:\s+([0-9a-f]+):([0-9a-f]+)', line)
                device_id = f"{device_match.group(1)}:{device_match.group(2)}" if device_match else "unknown"
                
                self._process_captured_data(line, device_id)
                
            # Clean up
            process.terminate()
            
        except Exception as e:
            logger.error(f"Error in Linux USB capture: {e}")
    
    def _capture_macos(self):
        """Capture USB traffic on macOS."""
        try:
            # On macOS, we can use the system_profiler and ioreg to monitor USB activity
            # This is not a true traffic capture but can detect changes in USB devices
            
            while self.running:
                # Use ioreg to get USB device info
                cmd = ["ioreg", "-p", "IOUSB", "-l", "-w", "0"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Process the output
                current_device = None
                device_data = ""
                
                for line in result.stdout.split('\n'):
                    if "+-o" in line:
                        # New device section
                        if current_device and device_data:
                            self._process_captured_data(device_data, current_device)
                        
                        # Extract device ID
                        match = re.search(r'@([0-9a-f]+)', line)
                        current_device = match.group(1) if match else "unknown"
                        device_data = line
                    else:
                        device_data += "\n" + line
                
                # Process the last device
                if current_device and device_data:
                    self._process_captured_data(device_data, current_device)
                
                # Sleep a bit to avoid excessive CPU usage
                time.sleep(1.0)
                
        except Exception as e:
            logger.error(f"Error in macOS USB capture: {e}")
    
    def _capture_windows(self):
        """Capture USB traffic on Windows."""
        try:
            # On Windows, we can use PowerShell to get USB device information
            # This doesn't capture actual traffic but can monitor for new devices and changes
            
            while self.running:
                # Use PowerShell to get USB device information
                cmd = ["powershell", "-Command", "Get-PnpDevice -Class USB | ConvertTo-Json"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                try:
                    devices = json.loads(result.stdout)
                    if not isinstance(devices, list):
                        devices = [devices]
                        
                    for device in devices:
                        device_id = device.get('DeviceID', 'unknown')
                        self._process_captured_data(json.dumps(device), device_id)
                except json.JSONDecodeError:
                    pass
                
                # Sleep to avoid excessive CPU usage
                time.sleep(1.0)
                
        except Exception as e:
            logger.error(f"Error in Windows USB capture: {e}")
    
    def _analyze_traffic(self):
        """Analyze captured USB traffic for suspicious patterns."""
        while self.running or not self.traffic_queue.empty():
            try:
                # Get traffic data from the queue with a timeout
                try:
                    traffic_data = self.traffic_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                
                # Check if the device is in the whitelist
                device_id = traffic_data.get('device_id', 'unknown').lower()
                if device_id in self.whitelist:
                    # Skip analysis for whitelisted devices
                    traffic_data['whitelisted'] = True
                    traffic_data['suspicious'] = False
                else:
                    # Analyze for suspicious patterns
                    for pattern in self.suspicious_patterns:
                        # Skip "Large HID Payload" checks for system devices (reduces false positives)
                        if pattern.name == "Large HID Payload" and traffic_data.get('is_system', False):
                            continue
                            
                        if pattern.matches(traffic_data):
                            traffic_data['suspicious'] = True
                            traffic_data['matches'].append({
                                "pattern": pattern.name,
                                "description": pattern.description,
                                "severity": pattern.severity
                            })
                            
                            # Update device stats
                            if traffic_data['device_id'] in self.device_stats:
                                self.device_stats[traffic_data['device_id']]["suspicious_count"] += 1
                            
                            # For system devices that trigger alerts, add them to whitelist for future
                            if traffic_data.get('is_system', False):
                                self.whitelist[device_id] = True
                
                # Add to the traffic log
                self.traffic_log.append(traffic_data)
                
                # Limit the size of the traffic log
                if len(self.traffic_log) > 1000:
                    self.traffic_log = self.traffic_log[-1000:]
                
                # Call the alert callback if the traffic is suspicious and not whitelisted
                if traffic_data['suspicious'] and not traffic_data.get('whitelisted', False) and self.alert_callback:
                    self.alert_callback(traffic_data)
                    
                # Mark the queue item as processed
                self.traffic_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error analyzing USB traffic: {e}")
                
def create_analyzer(alert_callback=None):
    """Create and return a USB traffic analyzer."""
    return USBTrafficAnalyzer(alert_callback)