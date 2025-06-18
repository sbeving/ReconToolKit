"""
ReconToolKit Configuration Manager
Handles application configuration and settings management.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from core.database import DatabaseManager


class ConfigManager:
    """Manages application configuration and settings."""
    
    def __init__(self, db_manager: DatabaseManager = None):
        """
        Initialize the configuration manager.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
        """
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager or DatabaseManager()
        
        # Default configuration values
        self.defaults = {
            'theme': 'dark',
            'window_width': 1200,
            'window_height': 800,
            'max_threads': 10,
            'request_timeout': 30,
            'user_agent': 'ReconToolKit/1.0.0',
            'default_wordlist': 'common_subdomains.txt',
            'auto_save_results': True,
            'show_progress_details': True,
            'log_level': 'INFO',
            'proxy_enabled': False,
            'proxy_host': '',
            'proxy_port': '',
            'proxy_username': '',
            'proxy_password': '',
        }
        
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default configuration values into the database if they don't exist."""
        try:
            for key, value in self.defaults.items():
                existing_value = self.db_manager.get_config(key)
                if existing_value is None:
                    self.db_manager.set_config(key, str(value))
                    self.logger.debug(f"Set default config: {key} = {value}")
                    
        except Exception as e:
            self.logger.error(f"Error loading default configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key (str): Configuration key
            default (Any): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        try:
            value = self.db_manager.get_config(key)
            if value is None:
                return default if default is not None else self.defaults.get(key)
            
            # Try to convert to appropriate type
            return self._convert_value(value)
            
        except Exception as e:
            self.logger.error(f"Error getting configuration '{key}': {e}")
            return default if default is not None else self.defaults.get(key)
    
    def set(self, key: str, value: Any, encrypted: bool = False):
        """
        Set a configuration value.
        
        Args:
            key (str): Configuration key
            value (Any): Configuration value
            encrypted (bool): Whether to encrypt the value
        """
        try:
            self.db_manager.set_config(key, str(value), encrypted)
            self.logger.debug(f"Set configuration: {key} = {value}")
            
        except Exception as e:
            self.logger.error(f"Error setting configuration '{key}': {e}")
            raise
    
    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        try:
            # Try integer
            if '.' not in value:
                return int(value)
        except ValueError:
            pass
        
        try:
            # Try float
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get an API key for a specific service.
        
        Args:
            service (str): Service name (e.g., 'virustotal', 'shodan', 'hunter')
            
        Returns:
            Optional[str]: API key or None if not set
        """
        return self.db_manager.get_config(f"api_key_{service}")
    
    def set_api_key(self, service: str, api_key: str):
        """
        Set an API key for a specific service.
        
        Args:
            service (str): Service name
            api_key (str): API key
        """
        self.db_manager.set_config(f"api_key_{service}", api_key, encrypted=True)
        self.logger.info(f"Set API key for service: {service}")
    
    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration."""
        return {
            'enabled': self.get('proxy_enabled'),
            'host': self.get('proxy_host'),
            'port': self.get('proxy_port'),
            'username': self.get('proxy_username'),
            'password': self.get('proxy_password'),
        }
    
    def set_proxy_config(self, host: str, port: str, username: str = '', password: str = '', enabled: bool = True):
        """Set proxy configuration."""
        self.set('proxy_enabled', enabled)
        self.set('proxy_host', host)
        self.set('proxy_port', port)
        self.set('proxy_username', username)
        self.set('proxy_password', password, encrypted=True if password else False)
        self.logger.info("Updated proxy configuration")
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all non-sensitive configuration settings."""
        try:
            configs = self.db_manager.get_all_configs()
            
            # Convert string values to appropriate types
            converted_configs = {}
            for key, value in configs.items():
                # Skip sensitive keys
                if key.startswith('api_key_') or key.endswith('_password'):
                    continue
                converted_configs[key] = self._convert_value(value)
            
            return converted_configs
            
        except Exception as e:
            self.logger.error(f"Error getting all settings: {e}")
            return {}
    
    def export_settings(self, file_path: str, include_api_keys: bool = False):
        """
        Export settings to a JSON file.
        
        Args:
            file_path (str): Path to export file
            include_api_keys (bool): Whether to include API keys (encrypted)
        """
        try:
            settings = self.get_all_settings()
            
            if include_api_keys:
                # Get encrypted API keys
                all_configs = self.db_manager.get_all_configs()
                for key, value in all_configs.items():
                    if key.startswith('api_key_'):
                        settings[key] = f"[ENCRYPTED: {value[:20]}...]"
            
            with open(file_path, 'w') as f:
                json.dump(settings, f, indent=2)
            
            self.logger.info(f"Settings exported to: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting settings: {e}")
            raise
    
    def import_settings(self, file_path: str):
        """
        Import settings from a JSON file.
        
        Args:
            file_path (str): Path to import file
        """
        try:
            with open(file_path, 'r') as f:
                settings = json.load(f)
            
            for key, value in settings.items():
                # Skip encrypted values from export
                if isinstance(value, str) and value.startswith('[ENCRYPTED:'):
                    continue
                
                # Determine if this should be encrypted
                encrypted = key.startswith('api_key_') or key.endswith('_password')
                self.set(key, value, encrypted)
            
            self.logger.info(f"Settings imported from: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error importing settings: {e}")
            raise
    
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        try:
            for key, value in self.defaults.items():
                self.set(key, value)
            
            self.logger.info("Configuration reset to defaults")
            
        except Exception as e:
            self.logger.error(f"Error resetting configuration: {e}")
            raise
    
    def validate_settings(self) -> Dict[str, str]:
        """
        Validate current settings and return any issues.
        
        Returns:
            Dict[str, str]: Dictionary of setting keys and their validation errors
        """
        issues = {}
        
        try:
            # Validate numeric settings
            max_threads = self.get('max_threads')
            if max_threads < 1 or max_threads > 100:
                issues['max_threads'] = "Must be between 1 and 100"
            
            request_timeout = self.get('request_timeout')
            if request_timeout < 1 or request_timeout > 300:
                issues['request_timeout'] = "Must be between 1 and 300 seconds"
            
            # Validate proxy settings if enabled
            if self.get('proxy_enabled'):
                proxy_host = self.get('proxy_host')
                proxy_port = self.get('proxy_port')
                
                if not proxy_host:
                    issues['proxy_host'] = "Proxy host is required when proxy is enabled"
                
                if not proxy_port or not proxy_port.isdigit() or not (1 <= int(proxy_port) <= 65535):
                    issues['proxy_port'] = "Valid proxy port (1-65535) is required when proxy is enabled"
            
            # Validate theme
            theme = self.get('theme')
            if theme not in ['light', 'dark']:
                issues['theme'] = "Theme must be 'light' or 'dark'"
            
            # Validate log level
            log_level = self.get('log_level')
            if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                issues['log_level'] = "Invalid log level"
            
        except Exception as e:
            self.logger.error(f"Error validating settings: {e}")
            issues['general'] = str(e)
        
        return issues
