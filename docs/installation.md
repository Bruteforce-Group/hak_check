# HakCheck Installation Guide

This guide provides instructions for installing and setting up HakCheck on different operating systems.

## Prerequisites

HakCheck requires:

- Python 3.8 or newer
- libusb (on non-Windows systems)
- Administrative privileges (for full functionality)

## Installation

### Installing from Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/hak_check.git
   cd hak_check
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install the package**:
   ```bash
   pip install -e .
   ```

### Operating System-Specific Instructions

#### Linux

1. **Install required system packages**:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libusb-1.0-0-dev python3-dev
   
   # Fedora/RHEL
   sudo dnf install libusbx-devel python3-devel
   ```

2. **Setup udev rules for non-root access** (optional):
   Create a file at `/etc/udev/rules.d/99-hakcheck.rules` with:
   ```
   # Allow hakcheck to access USB devices
   SUBSYSTEM=="usb", MODE="0666"
   ```

   Then reload udev rules:
   ```bash
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

#### macOS

1. **Install libusb using Homebrew**:
   ```bash
   brew install libusb
   ```

#### Windows

1. **Install libusb driver**:
   For Windows, the pyUSB library needs libusb drivers. The easiest way is to use [Zadig](https://zadig.akeo.ie/) to install the appropriate driver for your USB devices.

2. **Note about Windows permissions**:
   Some features require admin privileges on Windows. Right-click on Command Prompt or PowerShell and select "Run as administrator" when running HakCheck.

## Verifying Installation

To verify that HakCheck is installed correctly:

```bash
hakcheck --scan-once
```

This should detect and list all USB devices currently connected to your system.

## Running with Elevated Privileges

For full functionality, especially keyboard input blocking, HakCheck needs elevated privileges:

- **Linux/macOS**: Use `sudo` before commands
  ```bash
  sudo hakcheck --block-keyboard
  ```
  
- **Windows**: Run Command Prompt or PowerShell as Administrator

## Creating a Virtual Environment (Recommended)

It's recommended to run HakCheck in a Python virtual environment:

```bash
# Create a virtual environment
python -m venv hakcheck-env

# Activate the environment
# On Linux/macOS
source hakcheck-env/bin/activate
# On Windows
hakcheck-env\Scripts\activate

# Install HakCheck in the virtual environment
pip install -e .
```

## Troubleshooting

### Common Issues

1. **Permission errors on USB devices**:
   - Make sure you're running with sufficient privileges
   - On Linux, check your udev rules

2. **Missing libusb**:
   - Verify that libusb is installed correctly
   - On Windows, ensure the correct drivers are installed

3. **Python version errors**:
   - Verify you're using Python 3.8 or newer
   - Check if multiple Python versions are installed

4. **ImportError for pyusb or other dependencies**:
   - Reinstall dependencies: `pip install -r requirements.txt`

### Getting Help

If you encounter issues not addressed here, please:

1. Check the [GitHub Issues](https://github.com/yourusername/hak_check/issues) for similar problems
2. Submit a new issue with details about your system and the error message

## Next Steps

After installation, refer to the [User Guide](./user_guide.md) for usage instructions and the [Security Notes](./security_notes.md) for information about security features and best practices.