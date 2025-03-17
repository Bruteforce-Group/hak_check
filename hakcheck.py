#!/usr/bin/env python3
"""
HakCheck Launcher Script
Launches the appropriate HakCheck interface based on arguments.
"""

import sys
import argparse
import logging

def setup_logging(verbose=False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('hakcheck.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main entry point for HakCheck."""
    parser = argparse.ArgumentParser(description="HakCheck - USB Security Scanner")
    
    # Interface options
    interface_group = parser.add_argument_group("Interface Options")
    interface_group.add_argument("--gui", action="store_true", help="Launch the graphical interface (default)")
    interface_group.add_argument("--cli", action="store_true", help="Launch the command-line interface")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-s", "--scan-once", action="store_true", help="Scan once and exit (CLI mode only)")
    scan_group.add_argument("-v", "--verbose", action="store_true", help="Show detailed device information")
    scan_group.add_argument("-i", "--interval", type=int, default=2, help="Scan interval in seconds (default: 2)")
    
    # Security options
    security_group = parser.add_argument_group("Security Options")
    security_group.add_argument("-d", "--disable-isolation", action="store_true", help="Disable isolation features (not recommended)")
    security_group.add_argument("-k", "--block-keyboard", action="store_true", help="Block keyboard input (requires admin privileges)")
    security_group.add_argument("-t", "--traffic-analysis", action="store_true", help="Enable traffic analysis")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    
    try:
        # Determine interface mode
        if args.cli:
            # CLI mode
            from src.main import main as cli_main
            # Convert namespace to dict and filter out interface-related args
            cli_args_dict = {k: v for k, v in vars(args).items() 
                            if k not in ["gui", "cli", "traffic_analysis"]}
            # Call the CLI main function
            sys.exit(cli_main(**cli_args_dict))
        else:
            # GUI mode (default)
            from src.gui import main as gui_main
            gui_main()
            
    except ImportError as e:
        print(f"Error importing required modules: {e}")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Error launching HakCheck: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())