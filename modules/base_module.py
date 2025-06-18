"""
Base Module Class for ReconToolKit
Provides common functionality for all reconnaissance modules.
"""

import logging
import threading
import time
from abc import abstractmethod
from typing import Dict, Any, List, Optional, Callable
from PyQt5.QtCore import QObject, pyqtSignal


class BaseModule(QObject):
    """Base class for all reconnaissance modules."""
    
    # Signals for progress updates
    progress_updated = pyqtSignal(str, int)  # message, percentage
    scan_completed = pyqtSignal(dict)  # results
    scan_error = pyqtSignal(str)  # error message
    
    def __init__(self, name: str, description: str, category: str):
        """
        Initialize the base module.
        
        Args:
            name (str): Module name
            description (str): Module description
            category (str): Module category (passive, active, utility)
        """
        super().__init__()
        
        self.name = name
        self.description = description
        self.category = category
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        self._running = False
        self._thread = None
        self._results = {}
        self._config = {}
    
    @abstractmethod
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """
        Get list of input fields required for this module.
        
        Returns:
            List[Dict[str, Any]]: List of input field definitions
                Each dict should contain: name, type, label, required, default
        """
        pass
    
    @abstractmethod
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        """
        Validate input parameters.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            
        Returns:
            Optional[str]: Error message if validation fails, None if valid
        """
        pass
    
    @abstractmethod
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the actual scan/reconnaissance.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            config (Dict[str, Any]): Configuration parameters
            
        Returns:
            Dict[str, Any]: Scan results
        """
        pass
    
    def start_scan(self, inputs: Dict[str, Any], config: Dict[str, Any] = None):
        """
        Start the scan in a separate thread.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            config (Dict[str, Any]): Configuration parameters
        """
        if self._running:
            self.logger.warning("Scan already running")
            return
        
        # Validate inputs
        error = self.validate_inputs(inputs)
        if error:
            self.scan_error.emit(error)
            return
        
        self._config = config or {}
        self._running = True
        
        # Start scan in thread
        self._thread = threading.Thread(
            target=self._run_scan_thread,
            args=(inputs,),
            daemon=True
        )
        self._thread.start()
        
        self.logger.info(f"Started scan: {self.name}")
    
    def stop_scan(self):
        """Stop the running scan."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self.logger.info(f"Stopping scan: {self.name}")
    
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self._running
    
    def get_results(self) -> Dict[str, Any]:
        """Get the last scan results."""
        return self._results.copy()
    
    def _run_scan_thread(self, inputs: Dict[str, Any]):
        """Run scan in thread wrapper."""
        try:
            self.progress_updated.emit("Starting scan...", 0)
            results = self.run_scan(inputs, self._config)
            
            self._results = results
            self.progress_updated.emit("Scan completed", 100)
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            self.scan_error.emit(str(e))
        
        finally:
            self._running = False
    
    def update_progress(self, message: str, percentage: int = -1):
        """
        Update scan progress.
        
        Args:
            message (str): Progress message
            percentage (int): Progress percentage (-1 for indeterminate)
        """
        self.progress_updated.emit(message, percentage)
    
    def get_timeout(self) -> int:
        """Get request timeout from config."""
        return self._config.get('request_timeout', 30)
    
    def get_user_agent(self) -> str:
        """Get user agent from config."""
        return self._config.get('user_agent', 'ReconToolKit/1.0.0')
    
    def get_proxy_config(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration."""
        if not self._config.get('proxy_enabled', False):
            return None
        
        return {
            'http': f"http://{self._config.get('proxy_host')}:{self._config.get('proxy_port')}",
            'https': f"http://{self._config.get('proxy_host')}:{self._config.get('proxy_port')}"
        }
    
    def should_continue(self) -> bool:
        """Check if scan should continue running."""
        return self._running
