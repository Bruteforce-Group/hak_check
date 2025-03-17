#!/usr/bin/env python3
"""
Tests for the USB device checker.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import USBDeviceChecker

class MockUSBDevice:
    """Mock USB device for testing."""
    def __init__(self, vendor_id, product_id, device_class=0, device_subclass=0, device_protocol=0):
        self.idVendor = vendor_id
        self.idProduct = product_id
        self.bDeviceClass = device_class
        self.bDeviceSubClass = device_subclass
        self.bDeviceProtocol = device_protocol
        self.iManufacturer = 1
        self.iProduct = 2
        self.iSerialNumber = 3
        self.configurations = []
        
    def __iter__(self):
        """Allow iteration over configurations."""
        return iter(self.configurations)
        
class MockConfiguration:
    """Mock USB configuration for testing."""
    def __init__(self):
        self.interfaces = []
        
    def __iter__(self):
        """Allow iteration over interfaces."""
        return iter(self.interfaces)
        
class MockInterface:
    """Mock USB interface for testing."""
    def __init__(self, interface_class, interface_subclass, interface_protocol=0):
        self.bInterfaceClass = interface_class
        self.bInterfaceSubClass = interface_subclass
        self.bInterfaceProtocol = interface_protocol
        self.endpoints = []
        
    def __iter__(self):
        """Allow iteration over endpoints."""
        return iter(self.endpoints)
        
    def __len__(self):
        """Return the number of endpoints."""
        return len(self.endpoints)
        
class MockEndpoint:
    """Mock USB endpoint for testing."""
    def __init__(self, address, attributes):
        self.bEndpointAddress = address
        self.bmAttributes = attributes

class TestUSBDeviceChecker(unittest.TestCase):
    """Tests for the USBDeviceChecker class."""
    
    def setUp(self):
        """Set up a checker instance for testing."""
        self.checker = USBDeviceChecker(verbose=False)
        
    def test_get_device_signature(self):
        """Test the device signature generation."""
        device = MockUSBDevice(0x1234, 0x5678, 0, 0, 0)
        signature = self.checker.get_device_signature(device)
        self.assertEqual(signature, (0x1234, 0x5678, 0, 0, 0))
        
    def test_is_suspicious_device_by_vendor_product(self):
        """Test detection of suspicious devices by vendor/product ID."""
        # Create a device with a suspicious vendor/product ID
        device = MockUSBDevice(0x03eb, 0x2402)  # Teensy
        
        # Test if it's detected as suspicious
        self.assertTrue(self.checker.is_suspicious_device(device))
        
    def test_is_suspicious_device_by_class(self):
        """Test detection of suspicious devices by device class."""
        # Create a device with a suspicious class
        device = MockUSBDevice(0x9999, 0x9999, 0x03, 0x01)  # HID Keyboard
        
        # Test if it's detected as suspicious
        self.assertTrue(self.checker.is_suspicious_device(device))
        
    def test_non_suspicious_device(self):
        """Test that normal devices are not flagged as suspicious."""
        # Create a non-suspicious device
        device = MockUSBDevice(0x8888, 0x8888, 0x08, 0x06)  # Mass storage device
        
        # Test that it's not detected as suspicious
        self.assertFalse(self.checker.is_suspicious_device(device))
        
    @patch('usb.util.get_string')
    def test_get_device_info(self, mock_get_string):
        """Test device info collection."""
        # Set up the mock
        mock_get_string.return_value = "Test String"
        
        # Create a test device
        device = MockUSBDevice(0x1234, 0x5678, 0x08, 0x06)
        
        # Create a mock configuration
        config = MockConfiguration()
        
        # Create a mock interface
        interface = MockInterface(0x08, 0x06, 0x50)
        
        # Create mock endpoints
        endpoint1 = MockEndpoint(0x81, 0x02)
        endpoint2 = MockEndpoint(0x01, 0x02)
        
        # Add endpoints to interface
        interface.endpoints = [endpoint1, endpoint2]
        
        # Add interface to configuration
        config.interfaces = [interface]
        
        # Add configuration to device
        device.configurations = [config]
        
        # Get device info
        info = self.checker.get_device_info(device)
        
        # Check the info
        self.assertEqual(info["vendor_id"], hex(0x1234))
        self.assertEqual(info["product_id"], hex(0x5678))
        self.assertEqual(info["device_class"], 0x08)
        self.assertEqual(info["device_subclass"], 0x06)
        self.assertEqual(len(info["interfaces"]), 1)
        self.assertEqual(info["interfaces"][0]["interface_class"], 0x08)
        self.assertEqual(info["interfaces"][0]["interface_subclass"], 0x06)
        self.assertEqual(len(info["interfaces"][0]["endpoints"]), 2)

if __name__ == "__main__":
    unittest.main()