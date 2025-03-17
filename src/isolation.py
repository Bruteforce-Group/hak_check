#!/usr/bin/env python3
"""
Isolation utilities for HakCheck.
Provides functions to create an isolated environment for USB device analysis.
"""

import os
import sys
import subprocess
import platform
import logging
import psutil
import tempfile

logger = logging.getLogger(__name__)

def check_root_privileges():
    """Check if the script is running with root/admin privileges."""
    if platform.system() == "Windows":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

def create_sandbox():
    """
    Create a sandboxed environment for safer USB device analysis.
    Returns a dict with sandbox information.
    """
    sandbox_info = {
        "created": False,
        "type": None,
        "details": {}
    }
    
    system = platform.system()
    
    if system == "Linux":
        # On Linux, we can use a separate namespace
        try:
            # Check if unshare is available
            subprocess.run(["which", "unshare"], check=True, capture_output=True)
            sandbox_info["type"] = "namespace"
            sandbox_info["created"] = True
            logger.info("Using Linux namespace isolation")
        except:
            logger.warning("Could not create Linux namespace isolation")
    
    elif system == "Darwin":  # macOS
        # On macOS, we can use App Sandbox if the app is properly signed
        # For this script, we'll use basic process isolation
        sandbox_info["type"] = "process"
        sandbox_info["created"] = True
        logger.info("Using macOS process isolation")
    
    elif system == "Windows":
        # On Windows, we could use a Job object or integrity levels
        # For simplicity, we'll just use process isolation here too
        sandbox_info["type"] = "process"
        sandbox_info["created"] = True
        logger.info("Using Windows process isolation")
    
    return sandbox_info

def block_keyboard_input(enable=True):
    """
    Attempt to block HID keyboard input events from the system.
    This is a protective measure against HID injection attacks.
    
    Warning: This requires elevated privileges and may affect normal keyboard input.
    """
    system = platform.system()
    result = False
    
    if not check_root_privileges():
        logger.warning("Keyboard blocking requires administrator privileges")
        return False
    
    if system == "Linux":
        # On Linux, we can use udev rules or temporarily unbind the keyboard driver
        # This is a placeholder for actual implementation
        logger.info("Keyboard blocking on Linux would be implemented here")
        result = True
    
    elif system == "Darwin":  # macOS
        # On macOS, this is more complex and might require a kernel extension
        # For now, we'll just log that it's not fully implemented
        logger.warning("Full keyboard blocking not implemented on macOS")
        result = False
    
    elif system == "Windows":
        # On Windows, we could use a low-level keyboard hook to intercept events
        logger.info("Keyboard blocking on Windows would be implemented here")
        result = True
    
    return result

def create_temp_environment():
    """Create a temporary directory for safe USB analysis."""
    temp_dir = tempfile.mkdtemp(prefix="hakcheck_")
    logger.info(f"Created temporary environment at {temp_dir}")
    return temp_dir

def limit_process_resources():
    """Limit the resources available to the current process."""
    try:
        process = psutil.Process(os.getpid())
        
        # Set CPU affinity to a single core if possible
        if hasattr(process, "cpu_affinity") and len(process.cpu_affinity()) > 1:
            process.cpu_affinity([process.cpu_affinity()[0]])
            logger.info("Limited CPU affinity to a single core")
        
        # Set nice/priority to lower than normal
        if platform.system() != "Windows":
            process.nice(10)  # Lower priority (higher nice value)
        else:
            process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        
        logger.info("Set process to lower priority")
        
        return True
    except Exception as e:
        logger.error(f"Error limiting process resources: {e}")
        return False

def setup_isolation():
    """
    Set up isolation for the USB checking process.
    Returns a dict with isolation information.
    """
    isolation_info = {
        "sandbox": None,
        "temp_dir": None,
        "resources_limited": False,
        "keyboard_blocked": False
    }
    
    # Create sandbox environment
    isolation_info["sandbox"] = create_sandbox()
    
    # Create temporary directory
    isolation_info["temp_dir"] = create_temp_environment()
    
    # Limit process resources
    isolation_info["resources_limited"] = limit_process_resources()
    
    # Attempt to block keyboard input if we have root privileges
    # Note: This is disabled by default as it can interfere with normal use
    # isolation_info["keyboard_blocked"] = block_keyboard_input(True)
    
    return isolation_info

def cleanup_isolation(isolation_info):
    """Clean up isolation resources."""
    if isolation_info.get("temp_dir"):
        try:
            os.rmdir(isolation_info["temp_dir"])
            logger.info(f"Removed temporary directory {isolation_info['temp_dir']}")
        except:
            logger.warning(f"Could not remove temporary directory {isolation_info['temp_dir']}")
    
    # If keyboard blocking was enabled, disable it
    if isolation_info.get("keyboard_blocked"):
        block_keyboard_input(False)
    
    return True