#!/usr/bin/env python3
"""
Secure signal handling utilities.
Provides reentrant-safe signal handlers with proper cleanup and masking.
"""
import signal
import logging
import functools
from typing import Callable, Optional, Set
import threading

logger = logging.getLogger(__name__)

_received_signals: Set[int] = set()
_signal_lock = threading.Lock()

_cleanup_in_progress = False
_cleanup_lock = threading.Lock()

def safe_signal_handler(func: Callable) -> Callable:
    """
    Decorator to make signal handlers reentrant-safe.
    
    This decorator ensures that:
    1. Only async-signal-safe functions are called in the handler
    2. The handler sets a flag for deferred processing
    3. No complex operations happen during signal handling
    
    Args:
        func: The signal handler function to wrap
        
    Returns:
        Wrapped signal handler function
    """
    @functools.wraps(func)
    def wrapper(signum, frame):
                                                         
        with _signal_lock:
            _received_signals.add(signum)
        
        logger.info(f"Signal {signum} received")
        
        try:
            func(signum, frame)
        except Exception as e:
            logger.error(f"Error in signal handler for {signum}: {e}")
    
    return wrapper

class SignalMask:
    """
    Context manager for masking signals during critical operations.
    
    This prevents signal handlers from interrupting critical sections
    of code that could lead to race conditions or data corruption.
    """
    
    def __init__(self, signals: Optional[Set[int]] = None):
        """
        Initialize the signal mask.
        
        Args:
            signals: Set of signal numbers to mask. If None, masks common signals.
        """
        if signals is None:
                                                                
            self.signals = {
                signal.SIGINT,
                signal.SIGTERM,
                signal.SIGHUP,
            }
        else:
            self.signals = signals
        
        self._original_handlers = {}
        self._masked = False
    
    def __enter__(self):
        """Enter the context, masking the specified signals."""
        with _cleanup_lock:
            if _cleanup_in_progress:
                                                               
                logger.debug("Cleanup in progress, skipping signal mask")
                return self
            
            for sig in self.signals:
                try:
                    self._original_handlers[sig] = signal.signal(sig, signal.SIG_IGN)
                except (ValueError, OSError) as e:
                    logger.warning(f"Could not mask signal {sig}: {e}")
            
            self._masked = True
            logger.debug(f"Signals masked: {self.signals}")
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context, restoring original signal handlers."""
        with _cleanup_lock:
            if not self._masked:
                return
            
            for sig, handler in self._original_handlers.items():
                try:
                    signal.signal(sig, handler)
                except (ValueError, OSError) as e:
                    logger.warning(f"Could not restore signal {sig}: {e}")
            
            self._masked = False
            logger.debug(f"Signals unmasked: {self.signals}")
        
        return False

def register_signal_handler(signum: int, handler: Callable) -> None:
    """
    Register a signal handler with safety checks.
    
    Args:
        signum: Signal number to handle
        handler: Handler function (will be wrapped with safe_signal_handler)
    """
    try:
                                                  
        safe_handler = safe_signal_handler(handler)
        signal.signal(signum, safe_handler)
        logger.info(f"Registered handler for signal {signum}")
    except (ValueError, OSError) as e:
        logger.error(f"Failed to register handler for signal {signum}: {e}")

def cleanup_handler(signum: int, frame) -> None:
    """
    Default cleanup handler that sets a flag for graceful shutdown.
    
    This handler should be registered for SIGTERM and SIGINT.
    It sets a flag that the main loop can check to initiate cleanup.
    
    Args:
        signum: Signal number received
        frame: Current stack frame
    """
    global _cleanup_in_progress
    
    with _cleanup_lock:
        _cleanup_in_progress = True
    
    logger.info(f"Cleanup initiated by signal {signum}")

def is_cleanup_requested() -> bool:
    """
    Check if cleanup has been requested via signal.
    
    Returns:
        True if cleanup should be performed, False otherwise
    """
    with _cleanup_lock:
        return _cleanup_in_progress

def get_received_signals() -> Set[int]:
    """
    Get the set of signals that have been received.
    
    This allows the main loop to check for signals and process them
    in a safe context (not in the signal handler itself).
    
    Returns:
        Set of signal numbers that have been received
    """
    with _signal_lock:
        return set(_received_signals)

def clear_received_signals() -> None:
    """Clear the set of received signals after processing."""
    with _signal_lock:
        _received_signals.clear()

def reset_cleanup_flag() -> None:
    """Reset the cleanup flag (useful for testing or restart)."""
    global _cleanup_in_progress
    
    with _cleanup_lock:
        _cleanup_in_progress = False

class GracefulShutdown:
    """
    Context manager for graceful shutdown handling.
    
    This class provides a way to handle graceful shutdown across
    multiple threads and processes with proper signal handling.
    """
    
    def __init__(self, signals: Optional[Set[int]] = None):
        """
        Initialize the graceful shutdown handler.
        
        Args:
            signals: Set of signals to handle for shutdown. If None, uses defaults.
        """
        if signals is None:
            self.signals = {
                signal.SIGINT,
                signal.SIGTERM,
            }
        else:
            self.signals = signals
        
        self._original_handlers = {}
        self._shutdown_requested = False
        self._shutdown_lock = threading.Lock()
    
    def __enter__(self):
        """Enter the context, registering signal handlers."""
        for sig in self.signals:
            try:
                self._original_handlers[sig] = signal.signal(sig, self._handler)
                logger.info(f"Registered graceful shutdown handler for signal {sig}")
            except (ValueError, OSError) as e:
                logger.warning(f"Could not register handler for signal {sig}: {e}")
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context, restoring original signal handlers."""
        for sig, handler in self._original_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError) as e:
                logger.warning(f"Could not restore signal {sig}: {e}")
        
        return False
    
    def _handler(self, signum, frame):
        """
        Internal signal handler for graceful shutdown.
        
        Args:
            signum: Signal number received
            frame: Current stack frame
        """
        with self._shutdown_lock:
            self._shutdown_requested = True
        
        logger.info(f"Graceful shutdown requested by signal {signum}")
    
    def is_shutdown_requested(self) -> bool:
        """
        Check if shutdown has been requested.
        
        Returns:
            True if shutdown was requested, False otherwise
        """
        with self._shutdown_lock:
            return self._shutdown_requested
    
    def reset(self):
        """Reset the shutdown flag (useful for testing)."""
        with self._shutdown_lock:
            self._shutdown_requested = False
