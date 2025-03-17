# HakCheck

A comprehensive utility for safely detecting malicious USB devices (such as BadUSB, Rubber Ducky, or Hak5 devices) while isolating them from the rest of the system.

<div align="center">
  <img src="docs/images/logo.png" alt="HakCheck Logo" width="250">
</div>

## Overview

HakCheck provides a robust solution for checking USB devices for suspicious characteristics that might indicate malicious intent. Using multiple detection methods, sandboxed execution, and optional traffic analysis, it offers a safer way to examine untrusted USB devices before connecting them to sensitive systems.

## Key Features

### Detection Capabilities
- **Device Identification**: Comprehensive database of known suspicious USB device IDs
- **Behavioral Analysis**: Detects unusual device configurations and interface combinations
- **USB Traffic Monitoring**: Analyzes USB traffic for suspicious patterns (keystroke injection, etc.)
- **Risk Assessment**: Scores detected devices on a 1-10 risk scale with detailed explanations

### Safety & Isolation
- **Sandboxed Environment**: Platform-specific isolation to contain potential threats
- **Read-only Operation**: No data written to detected devices
- **No Driver Installation**: Prevents automatic driver loading for suspicious devices
- **Keyboard Blocking**: Optional feature to prevent HID injection attacks (requires admin privileges)

### User Interfaces
- **Modern GUI**: Clean graphical interface with device cards and detailed information
- **Command-line Interface**: For scriptable operation and headless environments
- **Real-time Monitoring**: Continuous device scanning with alerts for new connections

## Screenshots

<div align="center">
  <img src="docs/images/screenshot1.png" alt="HakCheck GUI" width="600">
  <p><i>Main application showing device listing</i></p>
</div>

<div align="center">
  <img src="docs/images/screenshot2.png" alt="Suspicious Device Alert" width="600">
  <p><i>Suspicious device detected with detailed analysis</i></p>
</div>

## Requirements

- **Python 3.8+**
- **Libraries**:
  - pyUSB (for USB device communication)
  - libusb (USB access layer)
  - psutil (for process isolation)
  - colorama (for CLI output)
  - tkinter (for GUI, included with most Python installations)
- **System Requirements**:
  - Some features require administrator/root privileges
  - Platform-specific dependencies as detailed in the installation guide

## Installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hak_check.git
cd hak_check

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

For detailed platform-specific installation instructions, see [Installation Guide](docs/installation.md).

## Usage

### Graphical Interface

```bash
# Launch the GUI (default)
python hakcheck.py

# Launch with traffic analysis enabled
python hakcheck.py --traffic-analysis
```

### Command-line Interface

```bash
# Basic scan
python hakcheck.py --cli

# Scan once and exit
python hakcheck.py --cli --scan-once

# Verbose output with custom scan interval
python hakcheck.py --cli --verbose --interval 5
```

### Advanced Options

```bash
# Enable keyboard blocking (requires admin/root)
sudo python hakcheck.py --block-keyboard

# Disable isolation (not recommended)
python hakcheck.py --disable-isolation

# View all available options
python hakcheck.py --help
```

## Documentation

- [Security Notes](docs/security_notes.md) - Detailed explanation of security features and limitations
- [Installation Guide](docs/installation.md) - Platform-specific installation instructions
- [Enhancements](ENHANCEMENTS.md) - List of advanced features and improvements

## Supporting the Project

- **Report Issues**: If you encounter bugs or have suggestions, please open an issue
- **Contribute**: Pull requests with improvements are welcome
- **Spread the Word**: Share this tool with security professionals and IT administrators

## Security Considerations

While HakCheck is designed to safely examine USB devices, no security measure is absolute. For maximum security:

- Run HakCheck on a dedicated system not connected to sensitive networks
- Consider using a virtual machine with restricted host access
- For critical environments, consider hardware USB isolation devices in addition to software measures

## License

This project is licensed under the MIT License - see the LICENSE file for details.