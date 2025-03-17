#!/usr/bin/env python3
"""
Simple GUI runner for HakCheck.
This script launches the graphical user interface for HakCheck directly.
"""

import sys
import logging
from src.gui import main as gui_main

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hakcheck_gui.log'),
        logging.StreamHandler()
    ]
)

if __name__ == "__main__":
    # Launch the GUI
    try:
        gui_main()
    except Exception as e:
        print(f"Error launching HakCheck GUI: {e}")
        sys.exit(1)