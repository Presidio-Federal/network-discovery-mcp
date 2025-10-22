#!/usr/bin/env python3
"""
Test script to verify pybatfish can be imported correctly.
This script should be run inside the container to diagnose import issues.
"""

import sys
import traceback

print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")

try:
    import pybatfish
    print(f"Successfully imported pybatfish version {pybatfish.__version__}")
    
    # Try to import specific modules
    from pybatfish.client.commands import bf_init_snapshot, bf_set_network, bf_session
    print("Successfully imported pybatfish.client.commands")
    
    from pybatfish.question import bfq
    print("Successfully imported pybatfish.question")
    
    print("All pybatfish modules imported successfully!")
    
except ImportError as e:
    print(f"ImportError: {str(e)}")
    print(f"Traceback: {traceback.format_exc()}")
    
except Exception as e:
    print(f"Exception: {str(e)}")
    print(f"Traceback: {traceback.format_exc()}")

# Try to list installed packages
try:
    import subprocess
    result = subprocess.run(['pip', 'list'], capture_output=True, text=True)
    print(f"Installed packages:\n{result.stdout}")
except Exception as e:
    print(f"Failed to list packages: {str(e)}")
