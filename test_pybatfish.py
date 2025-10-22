#!/usr/bin/env python3
"""
Test script to verify pybatfish can be imported correctly.
This script should be run inside the container to diagnose import issues.
"""

import sys
import traceback
import os

print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print(f"PYTHONPATH environment variable: {os.environ.get('PYTHONPATH', 'Not set')}")

try:
    import pybatfish
    print(f"Successfully imported pybatfish version {pybatfish.__version__}")
    print(f"Pybatfish location: {pybatfish.__file__}")
    
    # Check what's in the pybatfish directory
    pybatfish_dir = os.path.dirname(pybatfish.__file__)
    print(f"Contents of {pybatfish_dir}:")
    for item in os.listdir(pybatfish_dir):
        print(f"  - {item}")
    
    # Check if client directory exists
    client_dir = os.path.join(pybatfish_dir, 'client')
    if os.path.exists(client_dir):
        print(f"Contents of {client_dir}:")
        for item in os.listdir(client_dir):
            print(f"  - {item}")
    else:
        print(f"Client directory does not exist: {client_dir}")
    
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
    
    # Check if pybatfish is installed with pip show
    print("\nDetailed pybatfish info:")
    result = subprocess.run(['pip', 'show', 'pybatfish'], capture_output=True, text=True)
    print(result.stdout)
except Exception as e:
    print(f"Failed to list packages: {str(e)}")
