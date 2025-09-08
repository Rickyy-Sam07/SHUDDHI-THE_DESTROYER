"""
Emergency Handler for Shuddh Data Wiper
=======================================

Provides emergency quit functionality to safely abort operations.
"""

import threading
import time
import sys
import os
import signal
from typing import Optional, Callable
import logging

class EmergencyHandler:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.logger = logging.getLogger(__name__)
        self.abort_flag = threading.Event()
        self.current_operation = None
        self.cleanup_callbacks = []
        self.emergency_triggered = False
        
        # Register signal handlers only once
        if not hasattr(signal, '_shuddh_handlers_registered'):
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal._shuddh_handlers_registered = True
            
        self._initialized = True
        
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C and termination signals"""
        self.logger.critical(f"Emergency signal received: {signum}")
        self.trigger_emergency_quit("System signal received")
    
    def register_cleanup(self, callback: Callable):
        """Register cleanup function to call during emergency quit"""
        self.cleanup_callbacks.append(callback)
    
    def set_current_operation(self, operation: str):
        """Set the current operation for emergency reporting"""
        self.current_operation = operation
        self.logger.info(f"Current operation: {operation}")
    
    def check_abort(self) -> bool:
        """Check if abort has been requested"""
        return self.abort_flag.is_set()
    
    def trigger_emergency_quit(self, reason: str = "User requested"):
        """Trigger emergency quit sequence"""
        if self.emergency_triggered:
            return  # Already in progress
            
        self.emergency_triggered = True
        self.abort_flag.set()
        
        self.logger.critical(f"EMERGENCY QUIT TRIGGERED: {reason}")
        self.logger.critical(f"Current operation: {self.current_operation or 'Unknown'}")
        
        # Execute cleanup callbacks
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Cleanup callback failed: {e}")
        
        # Force exit after brief delay
        threading.Timer(2.0, self._force_exit).start()
    
    def _force_exit(self):
        """Force application exit"""
        self.logger.critical("Force exiting application")
        try:
            # Final cleanup attempt
            self._final_cleanup()
        except Exception as e:
            self.logger.error(f"Final cleanup failed: {e}")
        finally:
            os._exit(1)
    
    def _final_cleanup(self):
        """Final cleanup before force exit"""
        try:
            # Close any open file handles
            import gc
            gc.collect()
            
            # Attempt to flush any pending I/O
            sys.stdout.flush()
            sys.stderr.flush()
            
            # Additional resource cleanup
            try:
                import threading
                for thread in threading.enumerate():
                    if thread != threading.current_thread() and thread.daemon:
                        thread.join(timeout=0.1)
            except Exception:
                pass
                
        except Exception as e:
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
            self.logger.error(f"Final cleanup error: {sanitized_error}")
    
    def safe_operation_wrapper(self, operation_func, operation_name: str, *args, **kwargs):
        """Wrapper for operations that can be safely aborted"""
        self.set_current_operation(operation_name)
        
        try:
            return operation_func(*args, **kwargs)
        except Exception as e:
            self.logger.error(f"Operation {operation_name} failed: {e}")
            self.trigger_emergency_quit(f"Operation failure: {e}")
            raise
        finally:
            self.set_current_operation(None)

# Global emergency handler instance
emergency_handler = EmergencyHandler()