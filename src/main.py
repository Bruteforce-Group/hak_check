#!/usr/bin/env python3
"""
HakCheck - A utility for safely detecting malicious USB devices.
"""

import sys
import usb.core
import usb.util
import time
import click
import logging
import os
from colorama import Fore, Style, init
from src.isolation import setup_isolation, cleanup_isolation, check_root_privileges, block_keyboard_input

# Initialize colorama
init()

# Configure logging
log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hakcheck.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Known suspicious vendor/product IDs
SUSPICIOUS_IDS = [
    # Common BadUSB platforms
    (0x03eb, 0x2402),  # Teensy (often used in BadUSB)
    (0x1b4f, 0x9205),  # SparkFun Pro Micro
    (0x2341, 0x8036),  # Arduino Leonardo
    (0x16c0, 0x05df),  # Digispark
    (0x1b4f, 0x9206),  # SparkFun Pro Micro 5V
    (0x1b4f, 0x9204),  # SparkFun Pro Micro 3.3V
    (0x1d50, 0x6089),  # LT4320 USB-Backdoor
    
    # Commercial hacking tools
    (0x20a0, 0x4173),  # USB Rubber Ducky gen 1
    (0x03eb, 0x2067),  # Atmel DFU (used by some Ducky clones)
    (0x0483, 0xdf11),  # MallinkDucky/STM32 based Rubber Ducky
    (0x0483, 0x5740),  # O.MG Cable
    (0x057e, 0x304a),  # Hak5 Rubber Ducky 3.0
    (0x046d, 0xc539),  # Hak5 Bash Bunny (disguised as Logitech device)
    (0x045e, 0x0800),  # Hak5 Key Croc (disguised as Microsoft device)
    
    # Common keystroke injection platforms
    (0x239a, 0x000c),  # Adafruit Trinket
    (0x239a, 0x800c),  # Adafruit Trinket bootloader
    (0x2e8a, 0x000a),  # Raspberry Pi Pico
    (0x2e8a, 0xf00a),  # Raspberry Pi Pico (mass storage mode)
    (0xf055, 0x9800),  # WiFi Ducky
    (0xcafe, 0x4011),  # MalDuino
]

# HID device classes and subclasses that could be suspicious
SUSPICIOUS_CLASSES = [
    (0x03, 0x01),  # HID device, keyboard
    (0x03, 0x00),  # HID device, generic
]

# Suspicious interface protocols
SUSPICIOUS_PROTOCOLS = [
    (0x03, 0x01, 0x01),  # HID keyboard
    (0x03, 0x00, 0x01),  # HID keyboard alternate
]

# Suspicious string descriptors that may indicate malicious devices
SUSPICIOUS_STRINGS = [
    "rubber ducky",
    "ducky",
    "duck",
    "bash bunny",
    "bunny",
    "keycroc",
    "omg",
    "malduino",
    "badusb",
    "teensy",
    "digispark",
    "pico",
    "hak5",
    "flipper",
    "zero",
]

class USBDeviceChecker:
    """Class for checking USB devices for suspicious characteristics."""
    
    def __init__(self, verbose=False, scan_interval=2):
        self.verbose = verbose
        self.scan_interval = scan_interval
        self.last_devices = set()
        self.suspicious_devices = []
    
    def get_device_signature(self, device):
        """Generate a unique signature for a USB device."""
        try:
            return (
                device.idVendor,
                device.idProduct,
                device.bDeviceClass,
                device.bDeviceSubClass,
                device.bDeviceProtocol
            )
        except:
            return None
    
    def is_suspicious_device(self, device):
        """Check if a device has suspicious characteristics."""
        suspicion_reasons = []
        
        # Check vendor/product ID
        if (device.idVendor, device.idProduct) in SUSPICIOUS_IDS:
            suspicion_reasons.append(f"Known suspicious vendor/product ID: {hex(device.idVendor)}/{hex(device.idProduct)}")
        
        # Check device class
        if (device.bDeviceClass, device.bDeviceSubClass) in SUSPICIOUS_CLASSES:
            suspicion_reasons.append(f"Suspicious device class/subclass: {device.bDeviceClass}/{device.bDeviceSubClass}")
        
        # Get string descriptors for checking against suspicious strings
        device_strings = []
        try:
            if device.iManufacturer:
                manufacturer = usb.util.get_string(device, device.iManufacturer).lower()
                device_strings.append(manufacturer)
        except:
            pass
            
        try:
            if device.iProduct:
                product = usb.util.get_string(device, device.iProduct).lower()
                device_strings.append(product)
        except:
            pass
            
        try:
            if device.iSerialNumber:
                serial = usb.util.get_string(device, device.iSerialNumber).lower()
                device_strings.append(serial)
        except:
            pass
        
        # Check for suspicious strings in device descriptors
        for susp_string in SUSPICIOUS_STRINGS:
            for dev_string in device_strings:
                if susp_string in dev_string:
                    suspicion_reasons.append(f"Suspicious string '{susp_string}' found in device descriptor")
                    break
        
        # Check for common obfuscation patterns in string descriptors
        for dev_string in device_strings:
            # Check for character replacement (l33t speak)
            if any(x in dev_string for x in ['h4k', 'h4x', 'r00t', 'cr4ck', 'expl0it']):
                suspicion_reasons.append("Suspicious obfuscated string patterns found")
                break
        
        # Check configurations for suspicious patterns
        composite_device = False
        has_hid_interface = False
        has_storage_interface = False
        has_keyboard_interface = False
        hid_interface_count = 0
        
        for cfg in device:
            for intf in cfg:
                # Check for HID interfaces, especially keyboards
                if intf.bInterfaceClass == 3:  # HID
                    has_hid_interface = True
                    hid_interface_count += 1
                    
                    if intf.bInterfaceSubClass == 1:  # Boot Interface
                        if intf.bInterfaceProtocol == 1:  # Keyboard
                            has_keyboard_interface = True
                            
                    # Check for suspicious interface combinations
                    if (intf.bInterfaceClass, intf.bInterfaceSubClass, intf.bInterfaceProtocol) in SUSPICIOUS_PROTOCOLS:
                        suspicion_reasons.append(f"Suspicious interface protocol: {intf.bInterfaceClass}/{intf.bInterfaceSubClass}/{intf.bInterfaceProtocol}")
                    
                    # Check for non-standard descriptors or multiple endpoints (unusually complex HID device)
                    if len(intf) > 2:
                        suspicion_reasons.append(f"Complex HID interface with {len(intf)} endpoints (more than typical)")
                
                # Check for mass storage interfaces
                if intf.bInterfaceClass == 8 and intf.bInterfaceSubClass == 6:  # Mass Storage, SCSI
                    has_storage_interface = True
        
        # Composite device with both storage and HID keyboard is suspicious (common in BadUSB)
        if has_storage_interface and has_keyboard_interface:
            composite_device = True
            suspicion_reasons.append("Composite device with both storage and keyboard interfaces (common BadUSB pattern)")
        
        # Multiple HID interfaces might be suspicious
        if hid_interface_count > 1:
            suspicion_reasons.append(f"Multiple HID interfaces ({hid_interface_count}) found")
        
        # Check for devices that claim to be something else but have HID interfaces
        if device.bDeviceClass != 3 and has_hid_interface:  # Not a HID device but has HID interface
            suspicion_reasons.append("Device claims to be non-HID but contains HID interfaces")
        
        # Check for unusual endpoint configurations
        if has_keyboard_interface:
            for cfg in device:
                for intf in cfg:
                    if intf.bInterfaceClass == 3 and intf.bInterfaceSubClass == 1 and intf.bInterfaceProtocol == 1:  # Keyboard
                        # Analyze endpoint attributes for unusual patterns
                        for ep in intf:
                            # Check for unusual endpoint attributes
                            if ep.bmAttributes & 0x03 != 0x03:  # Not interrupt endpoint
                                suspicion_reasons.append("Keyboard with non-standard endpoint types")
        
        # USB devices with zero interfaces are highly unusual and suspicious
        interface_count = sum(1 for cfg in device for _ in cfg)
        if interface_count == 0:
            suspicion_reasons.append("Device has zero interfaces (highly unusual)")
        
        # Compound assessment
        self.suspicion_reasons = suspicion_reasons
        return len(suspicion_reasons) > 0
    
    def get_device_info(self, device):
        """Get detailed information about a USB device."""
        info = {
            "vendor_id": hex(device.idVendor),
            "product_id": hex(device.idProduct),
            "manufacturer": None,
            "product": None,
            "serial": None,
            "device_class": device.bDeviceClass,
            "device_subclass": device.bDeviceSubClass,
            "interfaces": []
        }
        
        # Try to get string descriptors (safely)
        try:
            if device.iManufacturer:
                info["manufacturer"] = usb.util.get_string(device, device.iManufacturer)
        except:
            pass
            
        try:
            if device.iProduct:
                info["product"] = usb.util.get_string(device, device.iProduct)
        except:
            pass
            
        try:
            if device.iSerialNumber:
                info["serial"] = usb.util.get_string(device, device.iSerialNumber)
        except:
            pass
        
        # Get interface information
        for cfg in device:
            for intf in cfg:
                interface_info = {
                    "interface_class": intf.bInterfaceClass,
                    "interface_subclass": intf.bInterfaceSubClass,
                    "interface_protocol": intf.bInterfaceProtocol,
                    "endpoints": []
                }
                
                for ep in intf:
                    interface_info["endpoints"].append({
                        "address": ep.bEndpointAddress,
                        "type": ep.bmAttributes & 0x03
                    })
                
                info["interfaces"].append(interface_info)
        
        return info
    
    def print_device_info(self, device_info, suspicious=False):
        """Print information about a USB device."""
        color = Fore.RED if suspicious else Fore.GREEN
        print(f"{color}{'='*60}{Style.RESET_ALL}")
        print(f"{color}Vendor ID: {device_info['vendor_id']}{Style.RESET_ALL}")
        print(f"{color}Product ID: {device_info['product_id']}{Style.RESET_ALL}")
        
        if device_info['manufacturer']:
            print(f"Manufacturer: {device_info['manufacturer']}")
        if device_info['product']:
            print(f"Product: {device_info['product']}")
        if device_info['serial']:
            print(f"Serial: {device_info['serial']}")
            
        print(f"Device Class: {device_info['device_class']}")
        print(f"Device Subclass: {device_info['device_subclass']}")
        
        if suspicious:
            print(f"\n{Fore.RED}⚠️  SUSPICIOUS DEVICE DETECTED! ⚠️{Style.RESET_ALL}")
            
            if hasattr(self, 'suspicion_reasons') and self.suspicion_reasons:
                print(f"{Fore.YELLOW}Reasons for suspicion:{Style.RESET_ALL}")
                for i, reason in enumerate(self.suspicion_reasons, 1):
                    print(f"{Fore.YELLOW}  {i}. {reason}{Style.RESET_ALL}")
                print()
        
        # Display risk assessment score
        if suspicious:
            risk_score = min(10, len(self.suspicion_reasons) * 2) if hasattr(self, 'suspicion_reasons') else 5
            risk_color = Fore.RED if risk_score > 7 else (Fore.YELLOW if risk_score > 3 else Fore.GREEN)
            print(f"{risk_color}Risk Assessment: {risk_score}/10{Style.RESET_ALL}")
            
        if self.verbose or suspicious:
            print("\nInterfaces:")
            for i, interface in enumerate(device_info['interfaces']):
                intf_color = Fore.RED if interface['interface_class'] == 3 else Fore.CYAN
                print(f"  {intf_color}Interface {i}:{Style.RESET_ALL}")
                print(f"    Class: {interface['interface_class']} ({self.get_interface_class_name(interface['interface_class'])})")
                print(f"    Subclass: {interface['interface_subclass']}")
                print(f"    Protocol: {interface['interface_protocol']}")
                print("    Endpoints:")
                for ep in interface['endpoints']:
                    print(f"      Address: {ep['address']}, Type: {ep['type']} ({self.get_endpoint_type_name(ep['type'])})")
        
        print(f"{color}{'='*60}{Style.RESET_ALL}")
    
    def get_interface_class_name(self, class_id):
        """Convert interface class ID to a human-readable name."""
        class_names = {
            0: "Interface Association",
            1: "Audio",
            2: "Communications",
            3: "HID",
            5: "Physical",
            6: "Image",
            7: "Printer",
            8: "Mass Storage",
            9: "Hub",
            10: "CDC Data",
            11: "Smart Card",
            13: "Content Security",
            14: "Video",
            15: "Personal Healthcare",
            16: "Audio/Video",
            17: "Billboard",
            0xFF: "Vendor Specific"
        }
        return class_names.get(class_id, "Unknown")
    
    def get_endpoint_type_name(self, type_id):
        """Convert endpoint type ID to a human-readable name."""
        type_names = {
            0: "Control",
            1: "Isochronous",
            2: "Bulk",
            3: "Interrupt"
        }
        return type_names.get(type_id, "Unknown")
    
    def scan_devices(self):
        """Scan all USB devices and check for suspicious ones."""
        current_devices = set()
        suspicious_found = False
        devices_found = 0
        
        try:
            # Get all USB devices
            devices = usb.core.find(find_all=True)
            
            for device in devices:
                signature = self.get_device_signature(device)
                if not signature:
                    continue
                
                devices_found += 1
                current_devices.add(signature)
                
                # Process the device (process all if verbose mode is on, otherwise only new ones)
                if self.verbose or signature not in self.last_devices:
                    # Store current reasons for later retrieval (needed in print_device_info)
                    if hasattr(self, 'suspicion_reasons'):
                        self.suspicion_reasons = []
                        
                    device_info = self.get_device_info(device)
                    is_suspicious = self.is_suspicious_device(device)
                    
                    # Store the suspicion reasons in the device info for summary reports
                    if is_suspicious and hasattr(self, 'suspicion_reasons'):
                        device_info['suspicion_reasons'] = self.suspicion_reasons.copy()
                        device_info['risk_score'] = min(10, len(self.suspicion_reasons) * 2)
                    
                    if is_suspicious:
                        suspicious_found = True
                        # Only add to the list if not already there (by vendor/product ID)
                        if not any(d['vendor_id'] == device_info['vendor_id'] and 
                                  d['product_id'] == device_info['product_id'] for d in self.suspicious_devices):
                            self.suspicious_devices.append(device_info)
                            
                        logger.warning(f"Suspicious device detected: {device_info['vendor_id']}:{device_info['product_id']}")
                        logger.warning(f"Suspicion reasons: {', '.join(device_info.get('suspicion_reasons', []))}")
                    
                    self.print_device_info(device_info, suspicious=is_suspicious)
            
            # Update the list of known devices
            self.last_devices = current_devices
            
            # Log summary
            logger.info(f"Scan complete: {devices_found} devices found, {len(self.suspicious_devices)} suspicious")
            
            return suspicious_found
            
        except Exception as e:
            logger.error(f"Error scanning USB devices: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return False
    
    def monitor(self):
        """Continuously monitor for new USB devices."""
        print(f"{Fore.CYAN}Starting USB monitoring...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Press Ctrl+C to exit{Style.RESET_ALL}")
        
        try:
            while True:
                suspicious = self.scan_devices()
                if suspicious:
                    print(f"{Fore.RED}WARNING: Suspicious USB device detected!{Style.RESET_ALL}")
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}Monitoring stopped{Style.RESET_ALL}")

@click.command()
@click.option('--verbose', '-v', is_flag=True, help='Show detailed device information')
@click.option('--scan-once', '-s', is_flag=True, help='Scan once and exit')
@click.option('--interval', '-i', default=2, help='Scan interval in seconds')
@click.option('--disable-isolation', '-d', is_flag=True, help='Disable isolation features (not recommended)')
@click.option('--block-keyboard', '-k', is_flag=True, help='Block keyboard input (requires admin privileges)')
def main(verbose, scan_once, interval, disable_isolation, block_keyboard):
    """HakCheck - A utility for safely detecting malicious USB devices."""
    print(f"{Fore.CYAN}HakCheck - USB Security Scanner{Style.RESET_ALL}")
    
    # Check for admin privileges if keyboard blocking is requested
    if block_keyboard and not check_root_privileges():
        print(f"{Fore.RED}WARNING: Keyboard blocking requires administrator privileges.{Style.RESET_ALL}")
        print(f"{Fore.RED}Please run the script with sudo/admin privileges.{Style.RESET_ALL}")
        return 2
    
    # Set up isolation if not disabled
    isolation_info = None
    if not disable_isolation:
        print(f"{Fore.YELLOW}Setting up isolation environment...{Style.RESET_ALL}")
        isolation_info = setup_isolation()
        
        if isolation_info["sandbox"]["created"]:
            print(f"{Fore.GREEN}Isolation environment created ({isolation_info['sandbox']['type']}){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Limited isolation available on this system{Style.RESET_ALL}")
        
        # Enable keyboard blocking if requested (and we have admin privileges)
        if block_keyboard:
            isolation_info["keyboard_blocked"] = block_keyboard_input(True)
            if isolation_info["keyboard_blocked"]:
                print(f"{Fore.GREEN}Keyboard blocking enabled{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Could not enable keyboard blocking{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}WARNING: Running without isolation - this is less secure!{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}This tool runs in a protected environment to isolate USB devices{Style.RESET_ALL}")
    
    try:
        # Create and run the USB checker
        checker = USBDeviceChecker(verbose=verbose, scan_interval=interval)
        
        if scan_once:
            checker.scan_devices()
        else:
            checker.monitor()
        
        # Display summary of findings
        if checker.suspicious_devices:
            print(f"{Fore.RED}Summary of suspicious devices found:{Style.RESET_ALL}")
            for device in checker.suspicious_devices:
                print(f"- {device['vendor_id']}:{device['product_id']} - ", end="")
                if device['product']:
                    print(f"{device['product']}", end="")
                if device['manufacturer']:
                    print(f" ({device['manufacturer']})", end="")
                print()
            exit_code = 1
        else:
            print(f"{Fore.GREEN}No suspicious devices detected{Style.RESET_ALL}")
            exit_code = 0
            
    except Exception as e:
        logger.error(f"Error during USB checking: {e}")
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
        exit_code = 3
    
    finally:
        # Clean up isolation if it was set up
        if isolation_info:
            print(f"{Fore.YELLOW}Cleaning up isolation environment...{Style.RESET_ALL}")
            cleanup_isolation(isolation_info)
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main())