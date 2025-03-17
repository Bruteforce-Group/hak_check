#!/usr/bin/env python3
"""
USB Topology Visualization Module for HakCheck.
Provides a graphical representation of USB controllers and connected devices.
"""

import platform
import subprocess
import re
import json
import tkinter as tk
from tkinter import ttk
import logging

logger = logging.getLogger(__name__)

class USBDevice:
    """Represents a USB device in the topology."""
    
    def __init__(self, device_id, description=None, vendor_id=None, product_id=None, 
                 is_controller=False, port=None, parent=None):
        self.device_id = device_id
        self.description = description
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.is_controller = is_controller
        self.port = port
        self.parent = parent
        self.children = []
        self.suspicious = False
    
    def add_child(self, child):
        """Add a child device."""
        self.children.append(child)
        
    def to_dict(self):
        """Convert to dictionary representation."""
        result = {
            "id": self.device_id,
            "description": self.description or "Unknown Device",
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "is_controller": self.is_controller,
            "port": self.port,
            "suspicious": self.suspicious,
            "children": [child.to_dict() for child in self.children]
        }
        return result

class USBTopologyAnalyzer:
    """Class for analyzing and building USB device topology."""
    
    def __init__(self):
        self.system = platform.system()
        self.root_devices = []
        self.device_map = {}  # Maps device_id to USBDevice objects
        
    def get_topology(self):
        """Get the USB device topology."""
        self.root_devices = []
        self.device_map = {}
        
        if self.system == "Darwin":  # macOS
            self._get_macos_topology()
        elif self.system == "Linux":
            self._get_linux_topology()
        elif self.system == "Windows":
            self._get_windows_topology()
        else:
            logger.warning(f"USB topology visualization not supported on {self.system}")
            
        return self.root_devices
        
    def _get_macos_topology(self):
        """Get USB topology on macOS using ioreg."""
        try:
            # Run ioreg to get USB device tree
            result = subprocess.run(
                ["ioreg", "-p", "IOUSB", "-w", "0"], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Error running ioreg: {result.stderr}")
                return
            
            # Parse the output
            current_indent = 0
            current_device = None
            parent_stack = []
            
            for line in result.stdout.splitlines():
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Calculate the indent level
                indent = 0
                for char in line:
                    if char == ' ':
                        indent += 1
                    else:
                        break
                indent = indent // 2  # ioreg uses 2 spaces per level
                
                # Extract device information
                device_match = re.search(r'\\o([-+]o[^<]+)<([^>]+)>', line)
                if not device_match:
                    continue
                    
                device_id = device_match.group(2)
                
                # Extract device description, if possible
                desc_match = re.search(r'"USB Product Name" = "([^"]+)"', line)
                description = desc_match.group(1) if desc_match else None
                
                # Extract vendor and product IDs, if possible
                vid_match = re.search(r'"idVendor" = (\w+)', line)
                pid_match = re.search(r'"idProduct" = (\w+)', line)
                vendor_id = vid_match.group(1) if vid_match else None
                product_id = pid_match.group(1) if pid_match else None
                
                # Extract port info if it exists
                port_match = re.search(r'"port" = (\d+)', line)
                port = port_match.group(1) if port_match else None
                
                # Determine if it's a controller
                is_controller = "AppleUSBXHCI" in line or "AppleUSBUHCI" in line or "AppleUSBEHCI" in line
                
                # Create the device object
                device = USBDevice(
                    device_id=device_id,
                    description=description,
                    vendor_id=vendor_id,
                    product_id=product_id,
                    is_controller=is_controller,
                    port=port
                )
                
                self.device_map[device_id] = device
                
                # Handle indentation to build tree
                if indent == 0:
                    # Root device
                    self.root_devices.append(device)
                    parent_stack = [device]
                    current_indent = indent
                elif indent > current_indent:
                    # Child of the last device
                    parent = parent_stack[-1]
                    parent.add_child(device)
                    device.parent = parent
                    parent_stack.append(device)
                    current_indent = indent
                elif indent == current_indent:
                    # Sibling of the last device
                    parent_stack.pop()
                    parent = parent_stack[-1]
                    parent.add_child(device)
                    device.parent = parent
                    parent_stack.append(device)
                else:
                    # Go back up the tree
                    while indent <= current_indent:
                        parent_stack.pop()
                        current_indent -= 1
                    parent = parent_stack[-1]
                    parent.add_child(device)
                    device.parent = parent
                    parent_stack.append(device)
                    current_indent = indent
        
        except Exception as e:
            logger.error(f"Error analyzing macOS USB topology: {e}")
    
    def _get_linux_topology(self):
        """Get USB topology on Linux using lsusb."""
        try:
            # Run lsusb verbose mode to get detailed information
            result = subprocess.run(
                ["lsusb", "-v"], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Error running lsusb: {result.stderr}")
                return
                
            # Get the USB controller information
            controllers_result = subprocess.run(
                ["lspci", "-D", "-nn", "-v", "-d", "*:0c03*"],
                capture_output=True,
                text=True
            )
            
            # Parse lspci to find USB controllers
            controllers = []
            if controllers_result.returncode == 0:
                for line in controllers_result.stdout.splitlines():
                    controller_match = re.search(r'^([0-9a-f:.]+)', line)
                    if controller_match:
                        controller_id = controller_match.group(1)
                        desc_match = re.search(r'USB controller.*?([A-Za-z0-9]+)\s', line)
                        description = desc_match.group(1) if desc_match else "USB Controller"
                        
                        controller = USBDevice(
                            device_id=controller_id,
                            description=description,
                            is_controller=True
                        )
                        controllers.append(controller)
                        self.device_map[controller_id] = controller
                        self.root_devices.append(controller)
            
            # Parse lsusb output to get devices
            current_device = None
            current_bus = None
            current_port = None
            
            for line in result.stdout.splitlines():
                bus_device_match = re.search(r'^Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4}) (.*)', line)
                if bus_device_match:
                    bus_num = bus_device_match.group(1)
                    device_num = bus_device_match.group(2)
                    vendor_id = bus_device_match.group(3)
                    product_id = bus_device_match.group(4)
                    description = bus_device_match.group(5)
                    
                    device_id = f"{bus_num}.{device_num}"
                    current_device = USBDevice(
                        device_id=device_id,
                        description=description,
                        vendor_id=vendor_id,
                        product_id=product_id
                    )
                    self.device_map[device_id] = current_device
                    
                    # Find parent controller
                    if controllers:
                        # Attach to the first controller for simplicity
                        controllers[0].add_child(current_device)
                        current_device.parent = controllers[0]
                
                # Try to extract port information
                port_match = re.search(r'Port (\d+):', line)
                if port_match and current_device:
                    current_device.port = port_match.group(1)
                    
                # Try to extract parent device information
                parent_match = re.search(r'Parent Hub: ([0-9.]+)', line)
                if parent_match and current_device:
                    parent_id = parent_match.group(1)
                    if parent_id in self.device_map:
                        # Update parent-child relationship
                        self.device_map[parent_id].add_child(current_device)
                        current_device.parent = self.device_map[parent_id]
                        
                        # Remove from controller's direct children if it's now a child of another device
                        for controller in controllers:
                            if current_device in controller.children and controller != self.device_map[parent_id]:
                                controller.children.remove(current_device)
        
        except Exception as e:
            logger.error(f"Error analyzing Linux USB topology: {e}")
    
    def _get_windows_topology(self):
        """Get USB topology on Windows using PowerShell."""
        try:
            # Run PowerShell command to get USB controllers and devices
            commands = [
                # Get USB controllers
                "Get-PnpDevice -Class USB | Where-Object { $_.Service -eq 'USBSTOR' } | Select-Object -Property DeviceID, FriendlyName, InstanceId | ConvertTo-Json",
                # Get USB devices using WMI
                "Get-WmiObject Win32_USBControllerDevice | ForEach-Object { [wmi]($_.Dependent) } | Select-Object DeviceID, Caption, Description, Manufacturer, PNPDeviceID | ConvertTo-Json"
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    ["powershell", "-Command", cmd], 
                    capture_output=True, 
                    text=True
                )
                
                if result.returncode != 0:
                    logger.error(f"Error running PowerShell command: {result.stderr}")
                    continue
                
                # Parse the JSON output
                try:
                    devices_data = json.loads(result.stdout)
                    if not isinstance(devices_data, list):
                        devices_data = [devices_data]
                        
                    for device_data in devices_data:
                        device_id = device_data.get('DeviceID', device_data.get('PNPDeviceID', 'unknown'))
                        description = (device_data.get('FriendlyName') or 
                                    device_data.get('Caption') or 
                                    device_data.get('Description') or 
                                    "Unknown Device")
                                    
                        # Try to extract vendor and product IDs from the device ID
                        vid_pid_match = re.search(r'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})', device_id, re.IGNORECASE)
                        vendor_id = vid_pid_match.group(1) if vid_pid_match else None
                        product_id = vid_pid_match.group(2) if vid_pid_match else None
                        
                        # Determine if it's a controller
                        is_controller = 'controller' in description.lower() or 'hub' in description.lower()
                        
                        device = USBDevice(
                            device_id=device_id,
                            description=description,
                            vendor_id=vendor_id,
                            product_id=product_id,
                            is_controller=is_controller
                        )
                        
                        self.device_map[device_id] = device
                        
                        # For simplicity, add all controllers as root devices
                        if is_controller:
                            self.root_devices.append(device)
                        
                        # Try to extract parent information from the device ID
                        parent_match = re.search(r'\\([^\\&]+)\\', device_id)
                        if parent_match:
                            parent_id = parent_match.group(1)
                            if parent_id in self.device_map and parent_id != device_id:
                                self.device_map[parent_id].add_child(device)
                                device.parent = self.device_map[parent_id]
                            
                except json.JSONDecodeError:
                    logger.warning("Could not parse PowerShell output as JSON")
        
        except Exception as e:
            logger.error(f"Error analyzing Windows USB topology: {e}")
    
    def mark_suspicious_devices(self, suspicious_devices):
        """Mark devices as suspicious based on vendor/product IDs."""
        for device_id, device in self.device_map.items():
            for susp_device in suspicious_devices:
                if (device.vendor_id and device.product_id and 
                    device.vendor_id == susp_device.get('vendor_id', '').strip('0x') and 
                    device.product_id == susp_device.get('product_id', '').strip('0x')):
                    device.suspicious = True
                    break

class USBTopologyView(ttk.Frame):
    """Visual representation of USB topology."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.parent = parent
        self.analyzer = USBTopologyAnalyzer()
        self.suspicious_devices = []
        self.create_widgets()
        
    def create_widgets(self):
        """Create the topology view widgets."""
        # Top control frame
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(
            control_frame,
            text="Refresh Topology",
            command=self.refresh_topology
        ).pack(side="left", padx=5)
        
        # Help text
        ttk.Label(
            control_frame,
            text="USB Controller & Device Topology",
            font=("Helvetica", 11, "bold")
        ).pack(side="right", padx=5)
        
        # Tree view frame
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create the tree view
        self.tree = ttk.Treeview(tree_frame, columns=("Type", "ID", "Description"))
        self.tree.heading("#0", text="Device")
        self.tree.heading("Type", text="Type")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Description", text="Description")
        
        self.tree.column("#0", width=200)
        self.tree.column("Type", width=100)
        self.tree.column("ID", width=150)
        self.tree.column("Description", width=300)
        
        self.tree.tag_configure("controller", background="#e6f7ff")
        self.tree.tag_configure("device", background="#f5f5f5")
        self.tree.tag_configure("hub", background="#f0f7ff")
        self.tree.tag_configure("suspicious", background="#ffcccc", foreground="#cc0000")
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        
        # Information frame for selected device
        info_frame = ttk.LabelFrame(self, text="Device Details")
        info_frame.pack(fill="x", padx=5, pady=5)
        
        self.info_text = tk.Text(info_frame, height=6, wrap="word")
        self.info_text.pack(fill="x", padx=5, pady=5)
        self.info_text.config(state="disabled")
        
        # Add selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_device_select)
        
        # Initial refresh
        self.refresh_topology()
    
    def refresh_topology(self):
        """Refresh the USB device topology."""
        # Clear the tree
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Clear the info text
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        self.info_text.config(state="disabled")
        
        # Get the new topology
        root_devices = self.analyzer.get_topology()
        
        # Mark suspicious devices
        self.analyzer.mark_suspicious_devices(self.suspicious_devices)
        
        # Add devices to the tree
        for device in root_devices:
            self._add_device_to_tree("", device)
    
    def _add_device_to_tree(self, parent_id, device):
        """Add a device to the tree view."""
        # Determine device type
        if device.is_controller:
            device_type = "Controller"
            tags = ("controller",)
        elif "hub" in (device.description or "").lower():
            device_type = "Hub"
            tags = ("hub",)
        else:
            device_type = "Device"
            tags = ("device",)
            
        # Add suspicious tag if needed
        if device.suspicious:
            tags = tags + ("suspicious",)
        
        # Create display name
        name = device.description or "Unknown Device"
        if device.port:
            name = f"Port {device.port}: {name}"
            
        # Add to tree
        device_id = f"{device.vendor_id}:{device.product_id}" if device.vendor_id and device.product_id else "N/A"
        tree_id = self.tree.insert(
            parent_id,
            "end",
            text=name,
            values=(device_type, device_id, device.description),
            tags=tags
        )
        
        # Add children
        for child in device.children:
            self._add_device_to_tree(tree_id, child)
    
    def on_device_select(self, event):
        """Handle device selection in the tree."""
        selected_id = self.tree.selection()[0]
        item = self.tree.item(selected_id)
        
        # Get device info
        device_type = item["values"][0]
        device_id = item["values"][1]
        description = item["values"][2]
        
        # Update info text
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        
        info_text = f"Type: {device_type}\n"
        info_text += f"Device ID: {device_id}\n"
        info_text += f"Description: {description}\n"
        
        # Add path information
        path = []
        parent_id = self.tree.parent(selected_id)
        while parent_id:
            parent_item = self.tree.item(parent_id)
            path.insert(0, parent_item["text"])
            parent_id = self.tree.parent(parent_id)
            
        if path:
            info_text += f"Path: {' → '.join(path)} → {item['text']}\n"
            
        # Add warning if suspicious
        if "suspicious" in item["tags"]:
            info_text += "\nWARNING: This device exhibits suspicious characteristics!"
            
        self.info_text.insert(tk.END, info_text)
        self.info_text.config(state="disabled")
    
    def set_suspicious_devices(self, suspicious_devices):
        """Set the list of suspicious devices."""
        self.suspicious_devices = suspicious_devices
        self.refresh_topology()