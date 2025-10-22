#!/usr/bin/env python3
"""
Debug script to test direct connection to a router.
Run this script inside the container to debug connection issues.

Usage:
    python debug_router.py <hostname> <username> <password> [port]
"""

import sys
import logging
import json
from network_discovery.direct_connect import direct_collect_routing

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Main function to test direct connection."""
    if len(sys.argv) < 4:
        print("Usage: python debug_router.py <hostname> <username> <password> [port]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 22
    
    print(f"Connecting to {hostname}:{port} with username {username}")
    
    # Try to collect routing information
    result = direct_collect_routing(hostname, username, password, port)
    
    # Print the result
    print("\nRouting Collection Result:")
    print(json.dumps(result, indent=2))
    
    # Print summary
    if "default" in result and isinstance(result["default"], list):
        print(f"\nFound {len(result['default'])} routes in default VRF")
        
        # Print first few routes
        if result["default"]:
            print("\nSample routes:")
            for i, route in enumerate(result["default"][:5]):
                print(f"  {i+1}. {route}")
    
    # Print VRFs
    if "vrf" in result:
        print(f"\nFound {len(result['vrf'])} VRFs")
        for vrf, routes in result["vrf"].items():
            print(f"  - VRF {vrf}: {len(routes)} routes")

if __name__ == "__main__":
    main()
