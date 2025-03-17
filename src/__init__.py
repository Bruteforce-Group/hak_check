"""
HakCheck - A utility for safely detecting malicious USB devices.
"""

__version__ = '0.1.0'

# Import main modules to make them available as part of the package
from . import main
from . import isolation
from . import traffic_analyzer
from . import gui