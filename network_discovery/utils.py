"""
Utility functions for network discovery.

This module provides common utility functions including retry logic,
timeout handling, and other helpers.
"""

import asyncio
import functools
import logging
import time
from typing import Callable, Optional, Tuple, Type, Union

logger = logging.getLogger(__name__)


class RetryableError(Exception):
    """Base exception for errors that should be retried."""
    pass


class NonRetryableError(Exception):
    """Base exception for errors that should not be retried."""
    pass


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retriable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    non_retriable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
):
    """
    Decorator to retry a function with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts (default: 3)
        initial_delay: Initial delay in seconds (default: 1.0)
        max_delay: Maximum delay in seconds (default: 60.0)
        exponential_base: Base for exponential backoff (default: 2.0)
        retriable_exceptions: Tuple of exception types to retry (default: all except non_retriable)
        non_retriable_exceptions: Tuple of exception types to never retry (default: None)
    
    Example:
        @retry_with_backoff(max_attempts=3, initial_delay=1.0)
        async def connect_to_device(host, port):
            return await asyncio.open_connection(host, port)
    """
    if retriable_exceptions is None:
        # Common network-related retriable errors
        retriable_exceptions = (
            ConnectionError,
            ConnectionRefusedError,
            ConnectionResetError,
            TimeoutError,
            asyncio.TimeoutError,
            OSError,
            RetryableError,
        )
    
    if non_retriable_exceptions is None:
        non_retriable_exceptions = (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            NonRetryableError,
        )
    
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except non_retriable_exceptions as e:
                    # Don't retry these exceptions
                    logger.error(
                        f"{func.__name__} failed with non-retriable error: {type(e).__name__}: {str(e)}"
                    )
                    raise
                except retriable_exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {type(e).__name__}: {str(e)}"
                        )
                        raise
                    
                    # Log the retry
                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {type(e).__name__}: {str(e)}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    
                    # Wait before retrying
                    await asyncio.sleep(delay)
                    
                    # Calculate next delay with exponential backoff
                    delay = min(delay * exponential_base, max_delay)
                except Exception as e:
                    # Unexpected exception - log and re-raise
                    logger.error(
                        f"{func.__name__} failed with unexpected error: {type(e).__name__}: {str(e)}"
                    )
                    raise
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except non_retriable_exceptions as e:
                    # Don't retry these exceptions
                    logger.error(
                        f"{func.__name__} failed with non-retriable error: {type(e).__name__}: {str(e)}"
                    )
                    raise
                except retriable_exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {type(e).__name__}: {str(e)}"
                        )
                        raise
                    
                    # Log the retry
                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {type(e).__name__}: {str(e)}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    
                    # Wait before retrying
                    time.sleep(delay)
                    
                    # Calculate next delay with exponential backoff
                    delay = min(delay * exponential_base, max_delay)
                except Exception as e:
                    # Unexpected exception - log and re-raise
                    logger.error(
                        f"{func.__name__} failed with unexpected error: {type(e).__name__}: {str(e)}"
                    )
                    raise
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


async def with_timeout(
    coro,
    timeout: float,
    error_message: Optional[str] = None
):
    """
    Execute a coroutine with a timeout.
    
    Args:
        coro: Coroutine to execute
        timeout: Timeout in seconds
        error_message: Optional custom error message
    
    Returns:
        Result of the coroutine
    
    Raises:
        asyncio.TimeoutError: If the operation times out
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if error_message:
            logger.error(error_message)
        raise


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and other issues.
    
    Args:
        filename: Filename to sanitize
    
    Returns:
        Sanitized filename
    
    Raises:
        ValueError: If filename is invalid
    """
    # Remove any path components
    filename = filename.split('/')[-1].split('\\')[-1]
    
    # Check for path traversal attempts
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise ValueError(f"Invalid filename: {filename}")
    
    # Check for empty filename
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Check for only dots
    if filename.strip('.') == '':
        raise ValueError("Filename cannot be only dots")
    
    return filename


def mask_sensitive_data(data: dict, sensitive_keys: Optional[list] = None) -> dict:
    """
    Mask sensitive data in a dictionary for safe logging.
    
    Args:
        data: Dictionary to mask
        sensitive_keys: List of keys to mask (default: common password/secret keys)
    
    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = ['password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'key']
    
    masked_data = data.copy()
    
    for key, value in masked_data.items():
        if key.lower() in sensitive_keys:
            masked_data[key] = "***MASKED***"
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
    
    return masked_data

