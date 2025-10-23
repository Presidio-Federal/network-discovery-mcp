"""
Patch for pybatfish to fix URL construction issues.
This module monkey-patches the pybatfish.client.restv2helper module
to fix URL construction issues when using localhost:9997.
"""

import logging
import os
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

def apply_patches():
    """Apply monkey patches to fix pybatfish URL construction."""
    try:
        # Import the module we need to patch
        from pybatfish.client import restv2helper
        
        # Store the original _get function
        original_get = restv2helper._get
        
        # Define our patched version
        def patched_get(session, url_tail, params=None, stream=False, fail_fast=True):
            """
            Patched version of _get that fixes URL construction.
            """
            # Get the base URL from the session
            base_url = f"http://{session.host}"
            if not base_url.endswith('/'):
                base_url += '/'
                
            # Construct the full URL properly
            url = urljoin(base_url, url_tail.lstrip('/'))
            
            logger.debug(f"Making request to: {url}")
            
            # Call the original _get with our fixed URL
            return original_get(session, url_tail, params, stream, fail_fast)
        
        # Apply the patch
        restv2helper._get = patched_get
        logger.info("Successfully applied pybatfish URL construction patch")
        
    except ImportError:
        logger.warning("Could not patch pybatfish - module not available")
    except Exception as e:
        logger.error(f"Failed to patch pybatfish: {str(e)}")
