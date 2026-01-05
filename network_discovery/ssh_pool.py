"""
SSH Connection Pool for reusing connections across operations.

This module provides a connection pool to avoid establishing new SSH connections
for every operation, significantly improving performance.
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Tuple

import asyncssh

logger = logging.getLogger(__name__)

# SSH connection options for legacy device support
LEGACY_SSH_OPTIONS = {
    'server_host_key_algs': [
        'ssh-rsa',              # Legacy (required for ASAv, old IOS)
        'rsa-sha2-256',         # Modern RSA
        'rsa-sha2-512',
        'ssh-ed25519',          # Modern EdDSA
        'ecdsa-sha2-nistp256',  # Modern ECDSA
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521'
    ],
    'kex_algs': [
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group14-sha256',
        'diffie-hellman-group16-sha512',
        'diffie-hellman-group18-sha512',
        'diffie-hellman-group14-sha1',   # Legacy (required for old devices)
        'diffie-hellman-group1-sha1'     # Very old (required for very old devices)
    ],
    'encryption_algs': [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
        'aes128-cbc',            # Legacy
        'aes192-cbc',            # Legacy
        'aes256-cbc',            # Legacy
        '3des-cbc'               # Very old (required for very old devices)
    ],
    'mac_algs': [
        'hmac-sha2-256',
        'hmac-sha2-512',
        'hmac-sha1'              # Legacy
    ]
}


@dataclass
class PooledConnection:
    """Represents a pooled SSH connection."""
    connection: asyncssh.SSHClientConnection
    host: str
    port: int
    username: str
    created_at: float
    last_used: float
    use_count: int
    is_alive: bool = True


class SSHConnectionPool:
    """
    SSH Connection Pool for reusing connections.
    
    Features:
    - Connection reuse across operations
    - Automatic connection health checks
    - Connection timeout and cleanup
    - Per-host connection limits
    - Thread-safe async operations
    """
    
    def __init__(
        self,
        max_connections: int = 50,
        max_per_host: int = 5,
        connection_ttl: int = 300,  # 5 minutes
        idle_timeout: int = 60,     # 1 minute
    ):
        """
        Initialize SSH connection pool.
        
        Args:
            max_connections: Maximum total connections in pool
            max_per_host: Maximum connections per host
            connection_ttl: Time-to-live for connections (seconds)
            idle_timeout: Idle timeout before connection is closed (seconds)
        """
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.connection_ttl = connection_ttl
        self.idle_timeout = idle_timeout
        
        # Pool storage: {(host, port, username): [PooledConnection, ...]}
        self._pool: Dict[Tuple[str, int, str], list[PooledConnection]] = defaultdict(list)
        
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
        
        # Statistics
        self._stats = {
            'connections_created': 0,
            'connections_reused': 0,
            'connections_closed': 0,
            'pool_hits': 0,
            'pool_misses': 0,
        }
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        
        logger.info(f"SSH Connection Pool initialized: max={max_connections}, "
                   f"per_host={max_per_host}, ttl={connection_ttl}s")
    
    async def get_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        connect_timeout: int = 30
    ) -> PooledConnection:
        """
        Get a connection from the pool or create a new one.
        
        Args:
            host: Target hostname or IP
            port: SSH port
            username: SSH username
            password: SSH password
            connect_timeout: Connection timeout in seconds
            
        Returns:
            PooledConnection: Pooled SSH connection
        """
        key = (host, port, username)
        
        async with self._lock:
            # Try to get existing connection from pool
            connections = self._pool.get(key, [])
            
            # Find a healthy, available connection
            for conn in connections:
                if conn.is_alive and self._is_connection_valid(conn):
                    # Test if connection is still alive
                    try:
                        # Quick liveness check
                        await asyncio.wait_for(
                            conn.connection.run('echo ping', check=False),
                            timeout=2.0
                        )
                        
                        # Connection is good, reuse it
                        conn.last_used = time.time()
                        conn.use_count += 1
                        self._stats['connections_reused'] += 1
                        self._stats['pool_hits'] += 1
                        
                        logger.debug(f"Reusing connection to {host}:{port} "
                                   f"(use_count={conn.use_count})")
                        return conn
                    except Exception as e:
                        logger.debug(f"Connection to {host}:{port} failed health check: {e}")
                        conn.is_alive = False
                        continue
            
            # No valid connection found, create new one
            self._stats['pool_misses'] += 1
            
            # Check if we've hit per-host limit
            active_count = sum(1 for c in connections if c.is_alive)
            if active_count >= self.max_per_host:
                logger.warning(f"Max connections per host reached for {host}:{port}")
                # Close oldest connection to make room
                for conn in connections:
                    if conn.is_alive:
                        await self._close_connection(conn)
                        connections.remove(conn)
                        break
            
            # Check if we've hit total pool limit
            total_active = sum(
                sum(1 for c in conns if c.is_alive)
                for conns in self._pool.values()
            )
            if total_active >= self.max_connections:
                logger.warning(f"Max pool size reached ({self.max_connections})")
                # Close least recently used connection
                await self._evict_lru_connection()
        
        # Create new connection (outside lock to avoid blocking)
        logger.debug(f"Creating new connection to {host}:{port}")
        
        try:
            ssh_conn = await asyncio.wait_for(
                asyncssh.connect(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    connect_timeout=connect_timeout,
                    **LEGACY_SSH_OPTIONS
                ),
                timeout=connect_timeout + 5
            )
            
            pooled_conn = PooledConnection(
                connection=ssh_conn,
                host=host,
                port=port,
                username=username,
                created_at=time.time(),
                last_used=time.time(),
                use_count=1,
                is_alive=True
            )
            
            async with self._lock:
                self._pool[key].append(pooled_conn)
                self._stats['connections_created'] += 1
            
            logger.info(f"Created new SSH connection to {host}:{port}")
            return pooled_conn
            
        except Exception as e:
            logger.error(f"Failed to create SSH connection to {host}:{port}: {e}")
            raise
    
    async def return_connection(self, conn: PooledConnection):
        """
        Return a connection to the pool.
        
        Args:
            conn: Connection to return
        """
        # Just update last_used timestamp
        # Connection stays in pool for reuse
        conn.last_used = time.time()
        logger.debug(f"Returned connection to {conn.host}:{conn.port} to pool")
    
    async def close_connection(self, conn: PooledConnection):
        """
        Explicitly close a connection and remove from pool.
        
        Args:
            conn: Connection to close
        """
        async with self._lock:
            await self._close_connection(conn)
            
            key = (conn.host, conn.port, conn.username)
            if key in self._pool:
                try:
                    self._pool[key].remove(conn)
                except ValueError:
                    pass  # Already removed
    
    async def _close_connection(self, conn: PooledConnection):
        """Close a connection (internal, assumes lock is held)."""
        if conn.is_alive:
            try:
                conn.connection.close()
                await conn.connection.wait_closed()
                conn.is_alive = False
                self._stats['connections_closed'] += 1
                logger.debug(f"Closed connection to {conn.host}:{conn.port}")
            except Exception as e:
                logger.warning(f"Error closing connection to {conn.host}:{conn.port}: {e}")
    
    def _is_connection_valid(self, conn: PooledConnection) -> bool:
        """Check if a connection is still valid based on TTL and idle timeout."""
        now = time.time()
        
        # Check TTL
        if now - conn.created_at > self.connection_ttl:
            logger.debug(f"Connection to {conn.host}:{conn.port} exceeded TTL")
            return False
        
        # Check idle timeout
        if now - conn.last_used > self.idle_timeout:
            logger.debug(f"Connection to {conn.host}:{conn.port} exceeded idle timeout")
            return False
        
        return True
    
    async def _evict_lru_connection(self):
        """Evict least recently used connection (assumes lock is held)."""
        lru_conn = None
        lru_key = None
        lru_time = float('inf')
        
        for key, connections in self._pool.items():
            for conn in connections:
                if conn.is_alive and conn.last_used < lru_time:
                    lru_conn = conn
                    lru_key = key
                    lru_time = conn.last_used
        
        if lru_conn:
            await self._close_connection(lru_conn)
            if lru_key:
                self._pool[lru_key].remove(lru_conn)
            logger.debug(f"Evicted LRU connection to {lru_conn.host}:{lru_conn.port}")
    
    async def cleanup_idle_connections(self):
        """Clean up idle and expired connections."""
        async with self._lock:
            closed_count = 0
            
            for key, connections in list(self._pool.items()):
                for conn in list(connections):
                    if not conn.is_alive or not self._is_connection_valid(conn):
                        await self._close_connection(conn)
                        connections.remove(conn)
                        closed_count += 1
                
                # Remove empty connection lists
                if not connections:
                    del self._pool[key]
            
            if closed_count > 0:
                logger.info(f"Cleaned up {closed_count} idle/expired connections")
    
    async def start_cleanup_task(self):
        """Start background task for cleaning up idle connections."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Started SSH connection pool cleanup task")
    
    async def _cleanup_loop(self):
        """Background loop for cleaning up idle connections."""
        while True:
            try:
                await asyncio.sleep(30)  # Run every 30 seconds
                await self.cleanup_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def close_all(self):
        """Close all connections in the pool."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        async with self._lock:
            total_closed = 0
            for connections in self._pool.values():
                for conn in connections:
                    if conn.is_alive:
                        await self._close_connection(conn)
                        total_closed += 1
            
            self._pool.clear()
            logger.info(f"Closed all connections in pool (total: {total_closed})")
    
    def get_stats(self) -> Dict:
        """Get pool statistics."""
        total_connections = sum(len(conns) for conns in self._pool.values())
        active_connections = sum(
            sum(1 for c in conns if c.is_alive)
            for conns in self._pool.values()
        )
        
        return {
            **self._stats,
            'total_connections': total_connections,
            'active_connections': active_connections,
            'pool_size': len(self._pool),
            'hit_rate': (
                self._stats['pool_hits'] / 
                (self._stats['pool_hits'] + self._stats['pool_misses'])
                if (self._stats['pool_hits'] + self._stats['pool_misses']) > 0
                else 0.0
            )
        }


# Global connection pool instance
_global_pool: Optional[SSHConnectionPool] = None


def get_ssh_pool() -> SSHConnectionPool:
    """Get the global SSH connection pool instance."""
    global _global_pool
    if _global_pool is None:
        _global_pool = SSHConnectionPool()
    return _global_pool


async def initialize_ssh_pool(
    max_connections: int = 50,
    max_per_host: int = 5,
    connection_ttl: int = 300,
    idle_timeout: int = 60
):
    """Initialize the global SSH connection pool."""
    global _global_pool
    _global_pool = SSHConnectionPool(
        max_connections=max_connections,
        max_per_host=max_per_host,
        connection_ttl=connection_ttl,
        idle_timeout=idle_timeout
    )
    await _global_pool.start_cleanup_task()
    logger.info("Global SSH connection pool initialized")


async def close_ssh_pool():
    """Close the global SSH connection pool."""
    global _global_pool
    if _global_pool:
        await _global_pool.close_all()
        _global_pool = None
        logger.info("Global SSH connection pool closed")

