"""
Artifact content retrieval tool.

This module provides functionality to retrieve content from artifact files.
"""

import base64
import logging
import mimetypes
import os
from pathlib import Path
from typing import Dict, Any, Union, Tuple, Optional

from network_discovery.config import get_job_dir

# Configure logging
logger = logging.getLogger(__name__)

# Initialize mimetypes
mimetypes.init()

# Define text-based MIME types
TEXT_MIME_TYPES = [
    'text/',
    'application/json',
    'application/javascript',
    'application/xml',
    'application/xhtml+xml',
    'application/x-yaml',
]

# Maximum size for text files (1MB)
MAX_TEXT_SIZE = 1024 * 1024  # 1MB


def is_text_file(mime_type: str) -> bool:
    """
    Check if a MIME type corresponds to a text file.
    
    Args:
        mime_type: MIME type to check
        
    Returns:
        bool: True if it's a text file, False otherwise
    """
    return any(mime_type.startswith(text_type) for text_type in TEXT_MIME_TYPES)


def get_artifact_content(job_id: str, filename: str) -> Tuple[Dict[str, Any], Optional[str], int]:
    """
    Retrieve content from an artifact file.
    
    Args:
        job_id: Job identifier
        filename: Name of the file to retrieve
        
    Returns:
        Tuple containing:
        - Dict with response data
        - Optional MIME type (for raw responses)
        - HTTP status code
    """
    # Validate and sanitize inputs to prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        logger.warning(f"Attempted directory traversal: {job_id}/{filename}")
        return {"error": "Invalid filename", "path": filename}, None, 400
    
    # Get the job directory and file path
    job_dir = get_job_dir(job_id)
    file_path = job_dir / filename
    
    logger.info(f"Attempting to retrieve artifact: {file_path}")
    
    # Check if the file exists
    if not file_path.exists() or not file_path.is_file():
        logger.warning(f"File not found: {file_path}")
        
        # Debug: List what files ARE in the directory
        if job_dir.exists():
            try:
                files_in_dir = list(job_dir.iterdir())
                logger.warning(f"Files in job directory {job_dir}: {[f.name for f in files_in_dir]}")
            except Exception as e:
                logger.warning(f"Could not list directory contents: {e}")
        else:
            logger.warning(f"Job directory does not exist: {job_dir}")
        
        return {"error": "File not found", "path": str(file_path), "job_dir": str(job_dir)}, None, 404
    
    # Get file size
    file_size = file_path.stat().st_size
    
    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if not mime_type:
        # Default to application/octet-stream if MIME type can't be determined
        mime_type = 'application/octet-stream'
    
    logger.info(f"File {file_path} is {file_size} bytes with MIME type {mime_type}")
    
    try:
        # Handle text files and small files
        if is_text_file(mime_type) and file_size <= MAX_TEXT_SIZE:
            # Read as text
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # For API endpoint, return raw content with MIME type
            return {"filename": filename, "encoding": "utf-8", "content": content}, mime_type, 200
        else:
            # Read as binary and encode as base64
            with open(file_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode('ascii')
            
            # Return JSON with base64 encoding
            return {
                "filename": filename,
                "encoding": "base64",
                "content": content
            }, "application/json", 200
    
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return {"error": f"Failed to read file: {str(e)}"}, None, 500
