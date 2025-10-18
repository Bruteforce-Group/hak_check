#!/usr/bin/env python3
"""
Simple CLI runner for HakCheck.
This script launches the command-line version of HakCheck directly.
"""

import sys
import logging
import click
from src.main import main as cli_main

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hakcheck_cli.log'),
        logging.StreamHandler()
    ]
)

# Because we're using the Click-based CLI directly, let's use that instead
# of creating our own argument parser
if __name__ == "__main__":
    sys.exit(cli_main())