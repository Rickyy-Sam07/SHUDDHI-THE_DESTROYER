"""
Emergency Handler for Shuddh Data Wiper
=======================================

Provides comprehensive emergency quit functionality to safely abort operations.

Key Features:
- Multiple abort triggers (ESC key, Ctrl+C, window close, system signals)
- Singleton pattern ensures single instance across application
- Cleanup callback system for resource management
- Signal handling for system-level interrupts
- Force exit mechanism with timeout protection
- Thread-safe abort flag for operation coordination

Safety Mechanisms:
- Graceful cleanup before exit
- Resource leak prevention
- File handle closure
- Thread synchronization
- Timeout protection against hanging operations

Usage:
- Register cleanup functions with register_cleanup()
- Set current operation with set_current_operation()
- Check abort status with check_abort()
- Trigger emergency quit with trigger_emergency_quit()
"""

import threading
import time
import sys
import os
import signal
from typing import Optional, Callable
import logging

class EmergencyHandler:
    """Singleton emergency handler for safe operation abort
    
    Implements the singleton pattern to ensure only one emergency handler
    exists across the entire application. Provides multiple mechanisms
    for safely aborting data wipe operations.
    
    Thread Safety:
    - Uses threading.Event for cross-thread communication
    - Signal handlers are thread-safe
    - Cleanup callbacks executed in controlled manner
    
    Abort Triggers:
    - SIGINT (Ctrl+C)
    - SIGTERM (system termination)
    - ESC key (via GUI binding)
    - Window close events
    - Manual trigger_emergency_quit() calls
    """
    
    # Singleton implementation
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """Ensure only one instance exists (singleton pattern)"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize emergency handler with signal handlers and state tracking
        
        Only initializes once due to singleton pattern. Sets up signal handlers
        for system-level interrupts and initializes state tracking variables.
        """
        # Prevent multiple initialization
        if self._initialized:
            return
            
        self.logger = logging.getLogger(__name__)
        
        # Thread-safe abort flag - can be checked by any thread
        self.abort_flag = threading.Event()
        
        # State tracking
        self.current_operation = None      # Description of current operation
        self.cleanup_callbacks = []        # Functions to call during cleanup
        self.emergency_triggered = False   # Prevent multiple emergency sequences
        
        # Register system signal handlers (only once per process)
        # Use a marker on the signal module to prevent duplicate registration
        if not hasattr(signal, '_shuddh_handlers_registered'):
            signal.signal(signal.SIGINT, self._signal_handler)   # Ctrl+C
            signal.signal(signal.SIGTERM, self._signal_handler)  # System termination
            signal._shuddh_handlers_registered = True
            
        self._initialized = True
        
    def _signal_handler(self, signum, frame):
        """Handle system signals (Ctrl+C, SIGTERM) for emergency abort
        
        This handler is called by the operating system when specific signals
        are received. It must be robust and handle failures gracefully since
        it's the last line of defense for emergency situations.
        
        Signal Types:
        - SIGINT (2): Ctrl+C interrupt from user
        - SIGTERM (15): Termination request from system
        
        Args:
            signum (int): Signal number received
            frame: Current stack frame (unused)
        """
        try:
            self.logger.critical(f"Emergency signal received: {signum}")
            self.trigger_emergency_quit("System signal received")
        except Exception as e:
            # Fallback mechanism if normal logging/cleanup fails
            # Print directly to console and force exit
            print(f"Emergency signal {signum} - logging failed: {e}")
            os._exit(1)  # Immediate exit without cleanup
    
    def register_cleanup(self, callback: Callable):
        """Register cleanup function to call during emergency quit
        
        Cleanup functions are called in registration order during emergency
        quit sequences. They should be designed to:
        - Execute quickly (< 1 second)
        - Handle exceptions gracefully
        - Clean up specific resources (file handles, network connections, etc.)
        - Not depend on other cleanup functions
        
        Args:
            callback (Callable): Function to call during cleanup (no arguments)
        """
        self.cleanup_callbacks.append(callback)
    
    def set_current_operation(self, operation: str):
        """Set the current operation for emergency reporting
        
        Tracks the current operation so that emergency quit messages
        can provide context about what was interrupted. This helps
        with debugging and user communication.
        
        Args:
            operation (str): Description of current operation (e.g., "Data purification")
        """
        self.current_operation = operation
        if operation:
            self.logger.info(f"Current operation: {operation}")
        else:
            self.logger.info("Operation completed")
    
    def check_abort(self) -> bool:
        """Check if abort has been requested
        
        This method should be called periodically by long-running operations
        to check if an emergency abort has been requested. Operations should
        check this flag regularly and exit gracefully if it's set.
        
        Returns:
            bool: True if abort requested, False if operation should continue
        """
        return self.abort_flag.is_set()
    
    def trigger_emergency_quit(self, reason: str = "User requested"):
        """Trigger emergency quit sequence with cleanup and forced exit
        
        Initiates a controlled emergency shutdown sequence:
        1. Set abort flag to signal all operations to stop
        2. Execute all registered cleanup callbacks
        3. Start force exit timer as failsafe
        4. Log emergency details for debugging
        
        The force exit timer ensures the application terminates even if
        cleanup callbacks hang or fail to complete.
        
        Args:
            reason (str): Description of why emergency quit was triggered
        """
        # Prevent multiple emergency sequences from running simultaneously
        if self.emergency_triggered:
            return
            
        self.emergency_triggered = True
        
        # Signal all operations to abort immediately
        self.abort_flag.set()
        
        # Log emergency details for debugging and audit
        self.logger.critical(f"EMERGENCY QUIT TRIGGERED: {reason}")
        self.logger.critical(f"Current operation: {self.current_operation or 'Unknown'}")
        
        # Execute all registered cleanup callbacks
        # Each callback is isolated to prevent one failure from affecting others
        for i, callback in enumerate(self.cleanup_callbacks):
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Cleanup callback {i} failed: {e}")
        
        # Start force exit timer as failsafe (2 second timeout)
        # This ensures the application exits even if something hangs
        threading.Timer(2.0, self._force_exit).start()
    
    def _force_exit(self):
        """Force application exit as last resort
        
        Called by the emergency timer if normal cleanup doesn't complete
        within the timeout period. Performs final resource cleanup and
        forces process termination.
        
        This method is the absolute last resort and should only be reached
        if normal shutdown mechanisms fail.
        """
        self.logger.critical("Force exiting application")
        try:
            # Attempt final cleanup of critical resources
            self._final_cleanup()
        except Exception as e:
            self.logger.error(f"Final cleanup failed: {e}")
        finally:
            # Force immediate process termination
            # os._exit() bypasses normal Python cleanup and signal handlers
            os._exit(1)
    
    def _final_cleanup(self):
        """Final cleanup before force exit
        
        Performs last-ditch cleanup of system resources before forcing
        process termination. This cleanup is designed to be fast and
        robust, handling failures gracefully.
        
        Cleanup Actions:
        1. Force garbage collection to close file handles
        2. Flush pending I/O operations
        3. Attempt to join daemon threads with short timeout
        4. Log any cleanup failures for debugging
        """
        try:
            # Force garbage collection to close any unreferenced file handles
            import gc
            gc.collect()
            
            # Flush any pending output to ensure logs are written
            sys.stdout.flush()
            sys.stderr.flush()
            
            # Attempt to clean up daemon threads with short timeout
            try:
                import threading
                current_thread = threading.current_thread()
                
                # Give daemon threads a brief chance to exit cleanly
                for thread in threading.enumerate():
                    if thread != current_thread and thread.daemon:
                        thread.join(timeout=0.1)  # Very short timeout
                        
            except Exception as e:
                # Sanitize error messages to prevent log injection
                sanitized_error = str(e).replace('\n', ' ').replace('\r', '').replace('\t', ' ')[:200]
                self.logger.error(f"Thread cleanup error: {sanitized_error}")
                
        except Exception as e:
            # Log final cleanup errors but don't raise
            # At this point we're committed to exiting
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '').replace('\t', ' ')[:200]
            self.logger.error(f"Final cleanup error: {sanitized_error}")
    
    def safe_operation_wrapper(self, operation_func, operation_name: str, *args, **kwargs):
        """Wrapper for operations that can be safely aborted
        
        Provides a standardized way to execute operations with emergency
        abort support. Automatically handles operation tracking and
        triggers emergency quit on critical failures.
        
        Features:
        - Automatic operation name tracking
        - Exception handling with emergency quit on critical errors
        - Cleanup of operation state on completion
        
        Args:
            operation_func: Function to execute
            operation_name (str): Human-readable operation description
            *args: Arguments to pass to operation_func
            **kwargs: Keyword arguments to pass to operation_func
            
        Returns:
            Any: Return value from operation_func
            
        Raises:
            Exception: Re-raises exceptions from operation_func after logging
        """
        # Set operation name for emergency reporting
        self.set_current_operation(operation_name)
        
        try:
            # Execute the wrapped operation
            return operation_func(*args, **kwargs)
        except Exception as e:
            # Log the failure and trigger emergency quit for critical errors
            self.logger.error(f"Operation {operation_name} failed: {e}")
            self.trigger_emergency_quit(f"Operation failure: {e}")
            raise  # Re-raise the exception for caller handling
        finally:
            # Always clear operation name when done
            self.set_current_operation(None)

# Global emergency handler instance (singleton)
# This is the single point of access for emergency handling across the application
emergency_handler = EmergencyHandler()