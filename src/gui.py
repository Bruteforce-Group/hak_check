#!/usr/bin/env python3
"""
GUI interface for HakCheck.
Provides a graphical user interface for the USB device checker.
"""

import sys
import os
import signal
import threading
import time
import logging
import platform
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main import USBDeviceChecker
from src.isolation import setup_isolation, cleanup_isolation, check_root_privileges
from src.traffic_analyzer import create_analyzer
from src.topology import USBTopologyView

# Configure logging
logger = logging.getLogger(__name__)

# Color constants
COLORS = {
    "background": "#f0f0f0",
    "header": "#2c3e50",
    "text": "#333333",
    "button": "#3498db",
    "button_hover": "#2980b9",
    "success": "#27ae60",
    "warning": "#f39c12",
    "danger": "#e74c3c",
    "info": "#3498db"
}

class ScrollableFrame(ttk.Frame):
    """A scrollable frame for tkinter."""
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

class DeviceDetailWindow(tk.Toplevel):
    """Window showing detailed information about a USB device."""
    def __init__(self, parent, device_info):
        super().__init__(parent)
        self.device_info = device_info
        self.title(f"Device Details: {device_info.get('product', 'Unknown Device')}")
        self.geometry("600x500")
        self.create_widgets()
        
    def create_widgets(self):
        """Create the widgets for the device detail window."""
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        
        # Device header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill="x", pady=5)
        
        # Determine color based on suspicion
        is_suspicious = 'suspicion_reasons' in self.device_info
        title_color = COLORS["danger"] if is_suspicious else COLORS["success"]
        
        # Title
        title = self.device_info.get('product', 'Unknown Device')
        manufacturer = self.device_info.get('manufacturer', '')
        if manufacturer:
            title += f" ({manufacturer})"
            
        title_label = ttk.Label(
            header_frame, 
            text=title, 
            font=("Helvetica", 16, "bold"),
            foreground=title_color
        )
        title_label.pack(anchor="w")
        
        # Basic info
        info_frame = ttk.LabelFrame(frame, text="Device Information", padding=5)
        info_frame.pack(fill="x", pady=5)
        
        info_grid = ttk.Frame(info_frame)
        info_grid.pack(fill="x", padx=5, pady=5)
        
        # Create grid of device information
        row = 0
        for label, value in [
            ("Vendor ID:", self.device_info.get('vendor_id', 'Unknown')),
            ("Product ID:", self.device_info.get('product_id', 'Unknown')),
            ("Serial Number:", self.device_info.get('serial', 'Unknown')),
            ("Device Class:", f"{self.device_info.get('device_class', 'Unknown')}"),
            ("Device Subclass:", f"{self.device_info.get('device_subclass', 'Unknown')}"),
        ]:
            ttk.Label(info_grid, text=label, font=("Helvetica", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=5, pady=2
            )
            ttk.Label(info_grid, text=value).grid(
                row=row, column=1, sticky="w", padx=5, pady=2
            )
            row += 1
        
        # Suspicion information if applicable
        if is_suspicious:
            risk_score = self.device_info.get('risk_score', 5)
            risk_color = COLORS["danger"] if risk_score > 7 else (
                COLORS["warning"] if risk_score > 3 else COLORS["success"])
                
            suspicion_frame = ttk.LabelFrame(frame, text="Suspicion Information", padding=5)
            suspicion_frame.pack(fill="x", pady=5)
            
            ttk.Label(suspicion_frame, 
                text=f"Risk Assessment: {risk_score}/10", 
                font=("Helvetica", 11, "bold"),
                foreground=risk_color
            ).pack(anchor="w", padx=5, pady=2)
            
            reasons_text = scrolledtext.ScrolledText(suspicion_frame, wrap=tk.WORD, height=6)
            reasons_text.pack(fill="x", padx=5, pady=5)
            
            # Insert suspicion reasons
            for i, reason in enumerate(self.device_info.get('suspicion_reasons', []), 1):
                reasons_text.insert(tk.END, f"{i}. {reason}\n")
            
            reasons_text.configure(state="disabled")  # Make read-only
        
        # Interface information
        interfaces_frame = ttk.LabelFrame(frame, text="Interfaces", padding=5)
        interfaces_frame.pack(fill="both", expand=True, pady=5)
        
        # Create a notebook for interfaces
        interfaces_notebook = ttk.Notebook(interfaces_frame)
        interfaces_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a tab for each interface
        for i, interface in enumerate(self.device_info.get('interfaces', [])):
            interface_frame = ttk.Frame(interfaces_notebook, padding=5)
            interfaces_notebook.add(interface_frame, text=f"Interface {i}")
            
            # Interface details
            ttk.Label(interface_frame, 
                text=f"Class: {interface['interface_class']}",
                font=("Helvetica", 10, "bold")
            ).pack(anchor="w", pady=2)
            
            ttk.Label(interface_frame, 
                text=f"Subclass: {interface['interface_subclass']}",
            ).pack(anchor="w", pady=2)
            
            ttk.Label(interface_frame, 
                text=f"Protocol: {interface['interface_protocol']}",
            ).pack(anchor="w", pady=2)
            
            # Endpoints
            if interface['endpoints']:
                endpoints_frame = ttk.LabelFrame(interface_frame, text="Endpoints", padding=5)
                endpoints_frame.pack(fill="x", pady=5)
                
                for j, endpoint in enumerate(interface['endpoints']):
                    ttk.Label(endpoints_frame, 
                        text=f"Endpoint {j}: Address {endpoint['address']}, Type {endpoint['type']}",
                    ).pack(anchor="w", pady=1)
        
        # Close button
        ttk.Button(frame, text="Close", command=self.destroy).pack(pady=10)

class HakCheckGUI(tk.Tk):
    """Main GUI application for HakCheck."""
    def __init__(self):
        super().__init__()
        
        # Set up the main window
        self.title("HakCheck - USB Security Scanner")
        self.geometry("800x600")
        self.minsize(800, 600)
        
        # Set up styles
        self.configure_styles()
        
        # Set up variables
        self.is_scanning = False
        self.scan_thread = None
        self.traffic_analyzer = None
        self.isolation_info = None
        self.checker = USBDeviceChecker(verbose=True)
        self.devices = []
        self.suspicious_devices = []
        
        # Create widgets
        self.create_widgets()
        
        # Set up cleanup on exit
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Register signal handlers if on Unix-like system
        if platform.system() != "Windows":
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
    
    def configure_styles(self):
        """Configure ttk styles."""
        self.style = ttk.Style(self)
        
        # Configure button styles
        self.style.configure("TButton", font=("Helvetica", 11))
        self.style.configure("Scan.TButton", background=COLORS["button"])
        self.style.configure("Stop.TButton", background=COLORS["danger"])
        
        # Configure frame styles
        self.style.configure("TFrame", background=COLORS["background"])
        self.style.configure("Header.TFrame", background=COLORS["header"])
        
        # Configure label styles
        self.style.configure("Header.TLabel", 
            font=("Helvetica", 16, "bold"), 
            foreground="white",
            background=COLORS["header"]
        )
        self.style.configure("Subheader.TLabel", 
            font=("Helvetica", 12), 
            foreground="white",
            background=COLORS["header"]
        )
        
        # Configure other styles
        self.style.configure("Red.TLabel", foreground=COLORS["danger"])
        self.style.configure("Green.TLabel", foreground=COLORS["success"])
        self.style.configure("Yellow.TLabel", foreground=COLORS["warning"])
    
    def create_widgets(self):
        """Create the main GUI widgets."""
        # Main container
        main_container = ttk.Frame(self)
        main_container.pack(fill="both", expand=True)
        
        # Header
        header_frame = ttk.Frame(main_container, style="Header.TFrame")
        header_frame.pack(fill="x")
        
        header_label = ttk.Label(
            header_frame, 
            text="HakCheck - USB Security Scanner", 
            style="Header.TLabel"
        )
        header_label.pack(padx=10, pady=(10, 0), anchor="w")
        
        subheader_label = ttk.Label(
            header_frame, 
            text="Safely detect potentially malicious USB devices", 
            style="Subheader.TLabel"
        )
        subheader_label.pack(padx=10, pady=(0, 10), anchor="w")
        
        # Content frame
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel (controls)
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side="left", fill="y", padx=(0, 5))
        
        # Control panel
        control_frame = ttk.LabelFrame(left_panel, text="Controls", padding=10)
        control_frame.pack(fill="x", pady=(0, 10))
        
        # Scan options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill="x", pady=5)
        
        # Continuous monitoring checkbox
        self.continuous_var = tk.BooleanVar(value=True)
        continuous_cb = ttk.Checkbutton(
            options_frame, 
            text="Continuous Monitoring", 
            variable=self.continuous_var
        )
        continuous_cb.grid(row=0, column=0, sticky="w", pady=2)
        
        # Verbose mode checkbox
        self.verbose_var = tk.BooleanVar(value=True)
        verbose_cb = ttk.Checkbutton(
            options_frame, 
            text="Verbose Mode", 
            variable=self.verbose_var
        )
        verbose_cb.grid(row=1, column=0, sticky="w", pady=2)
        
        # Traffic analysis checkbox
        self.traffic_analysis_var = tk.BooleanVar(value=False)
        traffic_cb = ttk.Checkbutton(
            options_frame, 
            text="Traffic Analysis", 
            variable=self.traffic_analysis_var
        )
        traffic_cb.grid(row=2, column=0, sticky="w", pady=2)
        
        # Quiet mode (disable popup alerts)
        self.quiet_mode_var = tk.BooleanVar(value=True)
        quiet_cb = ttk.Checkbutton(
            options_frame, 
            text="Quiet Mode (No Popups)", 
            variable=self.quiet_mode_var
        )
        quiet_cb.grid(row=3, column=0, sticky="w", pady=2)
        
        # Isolation mode checkbox
        self.isolation_var = tk.BooleanVar(value=True)
        isolation_cb = ttk.Checkbutton(
            options_frame, 
            text="Isolation Mode", 
            variable=self.isolation_var
        )
        isolation_cb.grid(row=4, column=0, sticky="w", pady=2)
        
        # Keyboard blocking checkbox
        self.keyboard_block_var = tk.BooleanVar(value=False)
        keyboard_cb = ttk.Checkbutton(
            options_frame, 
            text="Block Keyboard (Admin)", 
            variable=self.keyboard_block_var
        )
        keyboard_cb.grid(row=5, column=0, sticky="w", pady=2)
        
        # Scan interval slider
        interval_frame = ttk.Frame(control_frame)
        interval_frame.pack(fill="x", pady=5)
        
        ttk.Label(interval_frame, text="Scan Interval (seconds):").pack(anchor="w")
        
        self.interval_var = tk.IntVar(value=2)
        interval_scale = ttk.Scale(
            interval_frame, 
            from_=1, 
            to=10, 
            variable=self.interval_var, 
            orient="horizontal",
            command=lambda v: self.interval_label.config(text=f"{int(float(v))} sec")
        )
        interval_scale.pack(fill="x", pady=2)
        
        self.interval_label = ttk.Label(interval_frame, text="2 sec")
        self.interval_label.pack(anchor="e")
        
        # Buttons
        buttons_frame = ttk.Frame(control_frame)
        buttons_frame.pack(fill="x", pady=5)
        
        self.scan_button = ttk.Button(
            buttons_frame, 
            text="Start Scanning", 
            command=self.toggle_scan,
            style="Scan.TButton"
        )
        self.scan_button.pack(fill="x", pady=2)
        
        ttk.Button(
            buttons_frame,
            text="Clear Log",
            command=self.clear_log
        ).pack(fill="x", pady=2)
        
        ttk.Button(
            buttons_frame,
            text="Clear Alerts",
            command=self.clear_alerts
        ).pack(fill="x", pady=2)
        
        # Status information
        status_frame = ttk.LabelFrame(left_panel, text="Status", padding=10)
        status_frame.pack(fill="x")
        
        # Privilege level
        privilege_frame = ttk.Frame(status_frame)
        privilege_frame.pack(fill="x", pady=2)
        
        ttk.Label(privilege_frame, text="Privilege Level:").grid(row=0, column=0, sticky="w")
        
        if check_root_privileges():
            self.privilege_label = ttk.Label(
                privilege_frame, 
                text="Administrator", 
                style="Green.TLabel"
            )
        else:
            self.privilege_label = ttk.Label(
                privilege_frame, 
                text="Standard User", 
                style="Yellow.TLabel"
            )
        self.privilege_label.grid(row=0, column=1, sticky="w", padx=5)
        
        # Scanning status
        scan_status_frame = ttk.Frame(status_frame)
        scan_status_frame.pack(fill="x", pady=2)
        
        ttk.Label(scan_status_frame, text="Scanning:").grid(row=0, column=0, sticky="w")
        
        self.scan_status_label = ttk.Label(
            scan_status_frame, 
            text="Stopped", 
            style="Yellow.TLabel"
        )
        self.scan_status_label.grid(row=0, column=1, sticky="w", padx=5)
        
        # Isolation status
        isolation_frame = ttk.Frame(status_frame)
        isolation_frame.pack(fill="x", pady=2)
        
        ttk.Label(isolation_frame, text="Isolation:").grid(row=0, column=0, sticky="w")
        
        self.isolation_status_label = ttk.Label(
            isolation_frame, 
            text="Not Active", 
            style="Yellow.TLabel"
        )
        self.isolation_status_label.grid(row=0, column=1, sticky="w", padx=5)
        
        # Devices found
        devices_frame = ttk.Frame(status_frame)
        devices_frame.pack(fill="x", pady=2)
        
        ttk.Label(devices_frame, text="Devices Found:").grid(row=0, column=0, sticky="w")
        
        self.devices_count_label = ttk.Label(
            devices_frame, 
            text="0", 
            style="Green.TLabel"
        )
        self.devices_count_label.grid(row=0, column=1, sticky="w", padx=5)
        
        # Suspicious devices
        suspicious_frame = ttk.Frame(status_frame)
        suspicious_frame.pack(fill="x", pady=2)
        
        ttk.Label(suspicious_frame, text="Suspicious Devices:").grid(row=0, column=0, sticky="w")
        
        self.suspicious_count_label = ttk.Label(
            suspicious_frame, 
            text="0", 
            style="Green.TLabel"
        )
        self.suspicious_count_label.grid(row=0, column=1, sticky="w", padx=5)
        
        # Right panel (content)
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        # Notebook for different views
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Devices tab
        devices_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(devices_tab, text="Devices")
        
        # Create scrollable frame for devices
        self.devices_frame = ScrollableFrame(devices_tab)
        self.devices_frame.pack(fill="both", expand=True)
        
        # Topology tab
        topology_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(topology_tab, text="USB Topology")
        
        # Create the topology view
        self.topology_view = USBTopologyView(topology_tab)
        self.topology_view.pack(fill="both", expand=True)
        
        # Traffic tab
        traffic_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(traffic_tab, text="Traffic Analysis")
        
        # Traffic analysis frame
        self.traffic_frame = ttk.Frame(traffic_tab)
        self.traffic_frame.pack(fill="both", expand=True)
        
        ttk.Label(
            self.traffic_frame, 
            text="Traffic analysis is not active", 
            font=("Helvetica", 12, "italic")
        ).pack(pady=20)
        
        # Log tab
        log_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(log_tab, text="Log")
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")  # Make read-only
        
        # Footer
        footer_frame = ttk.Frame(main_container)
        footer_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(
            footer_frame, 
            text=f"System: {platform.system()} {platform.release()} | HakCheck v0.1.0", 
            font=("Helvetica", 8)
        ).pack(side="left")
        
        self.status_label = ttk.Label(
            footer_frame, 
            text="Ready", 
            font=("Helvetica", 8)
        )
        self.status_label.pack(side="right")
    
    def update_status(self, message, color=None):
        """Update the status message."""
        self.status_label.config(text=message)
        if color:
            self.status_label.config(foreground=color)
    
    def log_message(self, message, level="INFO"):
        """Add a message to the log tab."""
        # Get the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Set the color based on the log level
        if level == "ERROR":
            tag = "error"
            color = COLORS["danger"]
        elif level == "WARNING":
            tag = "warning"
            color = COLORS["warning"]
        elif level == "SUCCESS":
            tag = "success"
            color = COLORS["success"]
        else:
            tag = "info"
            color = COLORS["text"]
        
        # Enable editing, add the message, then disable again
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{timestamp} - {level}: {message}\n", tag)
        self.log_text.tag_config(tag, foreground=color)
        self.log_text.see(tk.END)  # Scroll to the end
        self.log_text.configure(state="disabled")
    
    def clear_log(self):
        """Clear the log text."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")
        self.log_message("Log cleared", "INFO")
        
    def clear_alerts(self):
        """Clear all suspicious device alerts."""
        # Clear suspicious devices
        self.checker.suspicious_devices = []
        # Clear traffic log if it exists
        if hasattr(self, 'traffic_log_text'):
            self.traffic_log_text.configure(state="normal")
            self.traffic_log_text.delete(1.0, tk.END)
            self.traffic_log_text.configure(state="disabled")
        # Reset status display
        self.suspicious_count_label.config(text="0", style="Green.TLabel")
        self.update_status("Alerts cleared", COLORS["success"])
        self.log_message("All alerts cleared", "INFO")
        # Update devices display
        self.update_devices_display()
        # Update topology view
        if hasattr(self, 'topology_view'):
            self.topology_view.set_suspicious_devices([])
            self.topology_view.refresh_topology()
            
    def clear_traffic_log(self):
        """Clear the traffic log."""
        if hasattr(self, 'traffic_log_text'):
            self.traffic_log_text.configure(state="normal")
            self.traffic_log_text.delete(1.0, tk.END)
            self.traffic_log_text.configure(state="disabled")
            self.log_message("Traffic log cleared", "INFO")
            
    def whitelist_system_devices(self):
        """Add all current system devices to the whitelist."""
        if hasattr(self, 'traffic_analyzer') and self.traffic_analyzer:
            # Get system devices from current device list
            for device_id in self.devices:
                if isinstance(device_id, tuple) and len(device_id) >= 2:
                    # Format as VID:PID
                    vid_pid = f"{device_id[0]:04x}:{device_id[1]:04x}".lower()
                    self.traffic_analyzer.whitelist[vid_pid] = True
                    
            # Also whitelist common system device IDs
            # These are already in the analyzer's default whitelist,
            # but we'll log them for user visibility
            common_ids = ["unknown", "00000000", "01000000", "02000000"]
            for device_id in common_ids:
                self.traffic_analyzer.whitelist[device_id] = True
                
            self.log_message(f"Added system devices to traffic analyzer whitelist", "INFO")
            self.update_status("System devices whitelisted", COLORS["success"])
    
    def toggle_scan(self):
        """Toggle USB scanning on/off."""
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start USB scanning."""
        # Check if already scanning
        if self.is_scanning:
            return
        
        self.is_scanning = True
        
        # Update UI
        self.scan_button.config(text="Stop Scanning", style="Stop.TButton")
        self.scan_status_label.config(text="Active", style="Green.TLabel")
        self.update_status("Scanning started", COLORS["success"])
        self.log_message("USB scanning started", "INFO")
        
        # Set up isolation if enabled
        if self.isolation_var.get():
            self.isolation_info = setup_isolation()
            
            if self.isolation_info["sandbox"]["created"]:
                self.isolation_status_label.config(
                    text=f"Active ({self.isolation_info['sandbox']['type']})",
                    style="Green.TLabel"
                )
                self.log_message(
                    f"Isolation environment created: {self.isolation_info['sandbox']['type']}",
                    "SUCCESS"
                )
            else:
                self.isolation_status_label.config(
                    text="Limited",
                    style="Yellow.TLabel"
                )
                self.log_message(
                    "Limited isolation available on this system",
                    "WARNING"
                )
            
            # Handle keyboard blocking
            if self.keyboard_block_var.get():
                if check_root_privileges():
                    from src.isolation import block_keyboard_input
                    self.isolation_info["keyboard_blocked"] = block_keyboard_input(True)
                    if self.isolation_info["keyboard_blocked"]:
                        self.log_message("Keyboard blocking enabled", "SUCCESS")
                    else:
                        self.log_message("Could not enable keyboard blocking", "WARNING")
                else:
                    messagebox.showwarning(
                        "Administrator Privileges Required",
                        "Keyboard blocking requires administrator privileges.\n"
                        "Please restart the application with elevated privileges."
                    )
                    self.keyboard_block_var.set(False)
        else:
            self.isolation_status_label.config(
                text="Disabled",
                style="Red.TLabel"
            )
            self.log_message(
                "Running without isolation - this is less secure!",
                "WARNING"
            )
        
        # Start traffic analyzer if enabled
        if self.traffic_analysis_var.get():
            self.start_traffic_analyzer()
        
        # Configure the USB checker
        self.checker = USBDeviceChecker(
            verbose=self.verbose_var.get(),
            scan_interval=self.interval_var.get()
        )
        
        # Start the scan thread
        self.scan_thread = threading.Thread(
            target=self._scan_thread_func,
            daemon=True
        )
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop USB scanning."""
        # Check if already stopped
        if not self.is_scanning:
            return
        
        self.is_scanning = False
        
        # Update UI
        self.scan_button.config(text="Start Scanning", style="Scan.TButton")
        self.scan_status_label.config(text="Stopped", style="Yellow.TLabel")
        self.update_status("Scanning stopped", COLORS["warning"])
        self.log_message("USB scanning stopped", "INFO")
        
        # Stop traffic analyzer if running
        if self.traffic_analyzer:
            self.traffic_analyzer.stop()
            self.traffic_analyzer = None
            self.log_message("Traffic analyzer stopped", "INFO")
        
        # Clean up isolation if active
        if self.isolation_info:
            cleanup_isolation(self.isolation_info)
            self.isolation_info = None
            self.isolation_status_label.config(text="Not Active", style="Yellow.TLabel")
            self.log_message("Isolation environment cleaned up", "INFO")
        
        # Wait for scan thread to end
        if self.scan_thread:
            self.scan_thread.join(timeout=1.0)
    
    def start_traffic_analyzer(self):
        """Start the USB traffic analyzer."""
        if not self.traffic_analyzer:
            self.traffic_analyzer = create_analyzer(self.traffic_alert_callback)
            self.traffic_analyzer.start()
            self.log_message("Traffic analyzer started", "INFO")
            
            # Clear and update the traffic tab
            for widget in self.traffic_frame.winfo_children():
                widget.destroy()
                
            ttk.Label(
                self.traffic_frame, 
                text="Traffic Analysis Active", 
                font=("Helvetica", 12, "bold")
            ).pack(pady=(10, 5))
            
            ttk.Label(
                self.traffic_frame, 
                text="Monitoring USB traffic for suspicious patterns", 
                font=("Helvetica", 10)
            ).pack(pady=(0, 10))
            
            # Traffic controls
            traffic_controls = ttk.Frame(self.traffic_frame)
            traffic_controls.pack(fill="x", pady=5)
            
            ttk.Button(
                traffic_controls,
                text="Clear Traffic Log",
                command=self.clear_traffic_log
            ).pack(side="left", padx=5)
            
            ttk.Button(
                traffic_controls,
                text="Whitelist System Devices",
                command=self.whitelist_system_devices
            ).pack(side="left", padx=5)
            
            # Add traffic log
            traffic_log_frame = ttk.LabelFrame(self.traffic_frame, text="Traffic Log", padding=5)
            traffic_log_frame.pack(fill="both", expand=True, pady=5)
            
            self.traffic_log_text = scrolledtext.ScrolledText(traffic_log_frame, wrap=tk.WORD)
            self.traffic_log_text.pack(fill="both", expand=True)
            self.traffic_log_text.configure(state="disabled")  # Make read-only
    
    def traffic_alert_callback(self, traffic_data):
        """Handle alerts from the traffic analyzer."""
        if not self.is_scanning:
            return
            
        # Log the alert
        device_id = traffic_data.get('device_id', 'unknown')
        timestamp = traffic_data.get('timestamp', datetime.now().isoformat())
        
        alert_message = f"Suspicious USB traffic detected from device {device_id}"
        self.log_message(alert_message, "WARNING")
        
        # Update the traffic log
        if hasattr(self, 'traffic_log_text'):
            self.traffic_log_text.configure(state="normal")
            
            # Get enhanced device information
            device_name = traffic_data.get('device_name', 'Unknown Device')
            device_type = traffic_data.get('device_type', 'Unknown')
            is_system = traffic_data.get('is_system', False)
            
            # Format the alert with matches
            matches = traffic_data.get('matches', [])
            match_text = ""
            for match in matches:
                match_text += f"\n  - {match['pattern']}: {match['description']} (Severity: {match['severity']}/10)"
            
            # Add device details
            device_details = f"\nDevice Name: {device_name}"
            if device_type != "Unknown":
                device_details += f"\nDevice Type: {device_type}"
            if is_system:
                device_details += f"\nNote: This appears to be a system device (likely a false positive)"
            
            self.traffic_log_text.insert(
                tk.END, 
                f"{timestamp} - ALERT: {alert_message}{match_text}{device_details}\n\n",
                "alert"
            )
            self.traffic_log_text.tag_config("alert", foreground=COLORS["danger"])
            self.traffic_log_text.see(tk.END)
            self.traffic_log_text.configure(state="disabled")
            
        # Instead of a popup, just highlight the tab and flash a status message
        self.update_status(f"ALERT: Suspicious USB traffic from device {device_id}", COLORS["danger"])
        
        # Switch to the traffic tab automatically
        self.notebook.select(1)  # Traffic tab index is 1
    
    def _scan_thread_func(self):
        """Thread function for scanning USB devices."""
        continuous = self.continuous_var.get()
        
        try:
            if continuous:
                while self.is_scanning:
                    self._perform_scan()
                    # Wait for the specified interval
                    for _ in range(self.interval_var.get() * 10):  # 10 checks per second
                        if not self.is_scanning:
                            break
                        time.sleep(0.1)
            else:
                self._perform_scan()
                self.is_scanning = False
                # Update UI from the main thread
                self.after(0, self._update_ui_after_scan)
        except Exception as e:
            self.log_message(f"Error during scanning: {str(e)}", "ERROR")
            self.is_scanning = False
            # Update UI from the main thread
            self.after(0, self._update_ui_after_scan)
    
    def _perform_scan(self):
        """Perform a single USB scan and update the UI."""
        # Clear previous devices
        self.devices = []
        
        # Store the original suspicious devices list to detect new ones
        original_suspicious = self.checker.suspicious_devices.copy()
        
        # Perform the scan
        self.checker.scan_devices()
        
        # Get new devices
        self.devices = self.get_devices_from_checker()
        
        # Check for new suspicious devices
        new_suspicious = [d for d in self.checker.suspicious_devices if d not in original_suspicious]
        if new_suspicious:
            # Alert for new suspicious devices
            for device in new_suspicious:
                self.log_message(
                    f"Suspicious device detected: {device['vendor_id']}:{device['product_id']}",
                    "WARNING"
                )
                
                if 'suspicion_reasons' in device:
                    for reason in device['suspicion_reasons']:
                        self.log_message(f"  - {reason}", "WARNING")
                
                # Only show pop-up alert if it's a new device, not on every scan
                if device not in original_suspicious:
                    self.after(0, lambda d=device: self._show_suspicious_alert(d))
        
        # Update UI from the main thread
        self.after(0, self._update_ui_after_scan)
    
    def _show_suspicious_alert(self, device):
        """Show an alert for a suspicious device."""
        product = device.get('product', 'Unknown Device')
        vendor = device.get('manufacturer', 'Unknown Manufacturer')
        
        # Always update status and highlight the devices tab
        self.update_status(f"ALERT: Suspicious device '{product}' detected!", COLORS["danger"])
        self.notebook.select(0)  # Select the devices tab
        
        # Only show popup if quiet mode is disabled
        if not self.quiet_mode_var.get():
            messagebox.showwarning(
                "Suspicious USB Device Detected",
                f"A suspicious USB device has been detected!\n\n"
                f"Product: {product}\n"
                f"Manufacturer: {vendor}\n"
                f"Vendor ID: {device['vendor_id']}\n"
                f"Product ID: {device['product_id']}\n\n"
                f"This device may be malicious. See the Devices tab for details."
            )
    
    def _update_ui_after_scan(self):
        """Update the UI after a scan completes."""
        # Update device count labels
        self.devices_count_label.config(text=str(len(self.devices)))
        suspicious_count = len(self.checker.suspicious_devices)
        self.suspicious_count_label.config(text=str(suspicious_count))
        
        if suspicious_count > 0:
            self.suspicious_count_label.config(style="Red.TLabel")
        else:
            self.suspicious_count_label.config(style="Green.TLabel")
        
        # Update devices display
        self.update_devices_display()
        
        # Update topology view with suspicious devices
        if hasattr(self, 'topology_view'):
            self.topology_view.set_suspicious_devices(self.checker.suspicious_devices)
        
        # If single scan, update scan button
        if not self.continuous_var.get():
            self.scan_button.config(text="Start Scanning", style="Scan.TButton")
            self.scan_status_label.config(text="Stopped", style="Yellow.TLabel")
    
    def get_devices_from_checker(self):
        """Get a list of devices from the checker's last scan."""
        # In a real implementation, we would extract this from the checker's state
        # For now, we'll create a simple representation
        return self.checker.last_devices
    
    def update_devices_display(self):
        """Update the devices display in the UI."""
        # Clear the current display
        for widget in self.devices_frame.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Add a device card for each device
        if not self.checker.suspicious_devices and not self.devices:
            ttk.Label(
                self.devices_frame.scrollable_frame,
                text="No USB devices detected",
                font=("Helvetica", 12, "italic")
            ).pack(pady=20)
            return
        
        # First show suspicious devices
        if self.checker.suspicious_devices:
            suspicious_label = ttk.Label(
                self.devices_frame.scrollable_frame,
                text="⚠️ Suspicious Devices",
                font=("Helvetica", 12, "bold"),
                foreground=COLORS["danger"]
            )
            suspicious_label.pack(anchor="w", pady=(10, 5))
            
            for device in self.checker.suspicious_devices:
                self.create_device_card(device, True)
            
            # Separator
            ttk.Separator(self.devices_frame.scrollable_frame, orient="horizontal").pack(
                fill="x", pady=10
            )
        
        # Then show safe devices
        safe_label = ttk.Label(
            self.devices_frame.scrollable_frame,
            text="Safe Devices",
            font=("Helvetica", 12, "bold"),
            foreground=COLORS["success"]
        )
        safe_label.pack(anchor="w", pady=(10, 5))
        
        safe_device_count = 0
        for device_signature in self.devices:
            # Skip devices that are in the suspicious list
            is_suspicious = False
            for susp in self.checker.suspicious_devices:
                if (int(susp['vendor_id'], 16), int(susp['product_id'], 16)) == device_signature[:2]:
                    is_suspicious = True
                    break
                    
            if not is_suspicious:
                # Create a simple card for safe devices
                safe_frame = ttk.Frame(self.devices_frame.scrollable_frame, padding=5)
                safe_frame.pack(fill="x", pady=2)
                
                ttk.Label(
                    safe_frame,
                    text=f"Device {hex(device_signature[0])}:{hex(device_signature[1])}",
                    foreground=COLORS["success"]
                ).pack(anchor="w")
                
                safe_device_count += 1
        
        if safe_device_count == 0:
            ttk.Label(
                self.devices_frame.scrollable_frame,
                text="No safe devices detected",
                font=("Helvetica", 10, "italic")
            ).pack(pady=5)
    
    def create_device_card(self, device, suspicious=False):
        """Create a card display for a device."""
        # Create the card frame
        card_frame = ttk.Frame(self.devices_frame.scrollable_frame, padding=10)
        card_frame.pack(fill="x", pady=5)
        
        # Add a border to the card
        card_style = "suspicious" if suspicious else "safe"
        card_color = COLORS["danger"] if suspicious else COLORS["success"]
        
        # Set a colored border for the card frame
        card_frame.configure(style=f"{card_style}.TFrame")
        self.style.configure(f"{card_style}.TFrame", relief="solid", borderwidth=1, bordercolor=card_color)
        
        # Header with device name
        name = device.get('product', 'Unknown Device')
        manufacturer = device.get('manufacturer', '')
        
        if manufacturer:
            name += f" ({manufacturer})"
        
        header_frame = ttk.Frame(card_frame)
        header_frame.pack(fill="x", pady=(0, 5))
        
        header_label = ttk.Label(
            header_frame,
            text=name,
            font=("Helvetica", 12, "bold"),
            foreground=card_color
        )
        header_label.pack(side="left")
        
        # Device details frame
        details_frame = ttk.Frame(card_frame)
        details_frame.pack(fill="x")
        
        # Device ID
        id_frame = ttk.Frame(details_frame)
        id_frame.pack(fill="x", pady=2)
        
        ttk.Label(id_frame, text="Vendor/Product ID:").pack(side="left")
        ttk.Label(
            id_frame, 
            text=f"{device['vendor_id']}:{device['product_id']}",
            font=("Helvetica", 10, "bold")
        ).pack(side="left", padx=5)
        
        # If suspicious, show a risk score
        if suspicious and 'risk_score' in device:
            risk_score = device['risk_score']
            risk_color = COLORS["danger"] if risk_score > 7 else (
                COLORS["warning"] if risk_score > 3 else COLORS["success"])
                
            risk_frame = ttk.Frame(details_frame)
            risk_frame.pack(fill="x", pady=2)
            
            ttk.Label(risk_frame, text="Risk Score:").pack(side="left")
            ttk.Label(
                risk_frame, 
                text=f"{risk_score}/10",
                font=("Helvetica", 10, "bold"),
                foreground=risk_color
            ).pack(side="left", padx=5)
            
            # Suspicion reasons
            if 'suspicion_reasons' in device and device['suspicion_reasons']:
                reason_frame = ttk.LabelFrame(card_frame, text="Suspicion Reasons", padding=5)
                reason_frame.pack(fill="x", pady=5)
                
                for reason in device['suspicion_reasons'][:3]:  # Show at most 3 reasons
                    ttk.Label(reason_frame, text=f"• {reason}").pack(anchor="w", pady=1)
                    
                if len(device['suspicion_reasons']) > 3:
                    ttk.Label(
                        reason_frame, 
                        text=f"(+{len(device['suspicion_reasons']) - 3} more reasons...)",
                        font=("Helvetica", 8, "italic")
                    ).pack(anchor="w", pady=1)
        
        # Actions frame
        actions_frame = ttk.Frame(card_frame)
        actions_frame.pack(fill="x", pady=5)
        
        # View details button
        ttk.Button(
            actions_frame,
            text="View Details",
            command=lambda d=device: self.show_device_details(d)
        ).pack(side="right", padx=2)
    
    def show_device_details(self, device):
        """Show device details in a new window."""
        DeviceDetailWindow(self, device)
    
    def signal_handler(self, sig, frame):
        """Handle signals to clean up properly."""
        self.on_close()
    
    def on_close(self):
        """Clean up and exit when closing the application."""
        if self.is_scanning:
            self.stop_scan()
            
        # Give a moment for threads to clean up
        time.sleep(0.5)
        
        self.destroy()

def main():
    """Main entry point for the HakCheck GUI."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('hakcheck_gui.log'),
            logging.StreamHandler()
        ]
    )
    
    # Create and run the application
    app = HakCheckGUI()
    app.mainloop()

if __name__ == "__main__":
    main()