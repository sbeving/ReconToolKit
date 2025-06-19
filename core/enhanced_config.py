"""
Enhanced Configuration Manager
Advanced configuration management with profiles, validation, and auto-updates.
"""

import logging
import json
import os
import time
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from core.database import DatabaseManager


class ConfigProfile:
    """Configuration profile for different scan scenarios."""
    
    def __init__(self, name: str, description: str, config: Dict[str, Any]):
        self.name = name
        self.description = description
        self.config = config
        self.created_at = datetime.now()
        self.last_used = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'config': self.config,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigProfile':
        profile = cls(data['name'], data['description'], data['config'])
        profile.created_at = datetime.fromisoformat(data['created_at'])
        if data['last_used']:
            profile.last_used = datetime.fromisoformat(data['last_used'])
        return profile


class EnhancedConfigManager:
    """Enhanced configuration manager with profiles and advanced features."""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager or DatabaseManager()
        
        # Configuration profiles
        self.profiles = {}
        
        # Configuration validation rules
        self.validation_rules = {
            'timeout': {'type': int, 'min': 1, 'max': 300},
            'threads': {'type': int, 'min': 1, 'max': 1000},
            'max_redirects': {'type': int, 'min': 0, 'max': 50},
            'user_agent': {'type': str, 'min_length': 1},
            'proxy_port': {'type': int, 'min': 1, 'max': 65535},
            'rate_limit': {'type': float, 'min': 0.1, 'max': 60.0}
        }
        
        # Default configuration templates
        self.default_configs = {
            'stealth': {
                'name': 'Stealth Scanning',
                'description': 'Low-profile scanning to avoid detection',
                'config': {
                    'threads': 5,
                    'timeout': 30,
                    'rate_limit': 2.0,
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'max_redirects': 3,
                    'randomize_requests': True,
                    'use_proxy_rotation': True
                }
            },
            'aggressive': {
                'name': 'Aggressive Scanning',
                'description': 'Fast, comprehensive scanning',
                'config': {
                    'threads': 100,
                    'timeout': 10,
                    'rate_limit': 0.1,
                    'user_agent': 'ReconToolKit/1.0',
                    'max_redirects': 10,
                    'deep_scan': True,
                    'comprehensive_wordlists': True
                }
            },
            'balanced': {
                'name': 'Balanced Scanning',
                'description': 'Balanced speed and stealth',
                'config': {
                    'threads': 25,
                    'timeout': 15,
                    'rate_limit': 0.5,
                    'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                    'max_redirects': 5,
                    'moderate_scan': True
                }
            },
            'compliance': {
                'name': 'Compliance Scanning',
                'description': 'Compliance-focused security assessment',
                'config': {
                    'threads': 10,
                    'timeout': 30,
                    'rate_limit': 1.0,
                    'comprehensive_reporting': True,
                    'include_remediation': True,
                    'evidence_collection': True,
                    'detailed_logging': True
                }
            }
        }
        
        self._load_profiles()
        self._ensure_default_profiles()

    def _load_profiles(self):
        """Load configuration profiles from database."""
        try:
            profiles_data = self.db_manager.get_config('config_profiles', '{}')
            if profiles_data:
                profiles_dict = json.loads(profiles_data)
                for name, profile_data in profiles_dict.items():
                    self.profiles[name] = ConfigProfile.from_dict(profile_data)
        except Exception as e:
            self.logger.error(f"Error loading profiles: {e}")

    def _save_profiles(self):
        """Save configuration profiles to database."""
        try:
            profiles_dict = {name: profile.to_dict() for name, profile in self.profiles.items()}
            self.db_manager.set_config('config_profiles', json.dumps(profiles_dict))
        except Exception as e:
            self.logger.error(f"Error saving profiles: {e}")

    def _ensure_default_profiles(self):
        """Ensure default profiles exist."""
        for profile_name, profile_data in self.default_configs.items():
            if profile_name not in self.profiles:
                self.create_profile(
                    profile_data['name'],
                    profile_data['description'],
                    profile_data['config']
                )

    def create_profile(self, name: str, description: str, config: Dict[str, Any]) -> bool:
        """Create a new configuration profile."""
        try:
            # Validate configuration
            validation_errors = self.validate_config(config)
            if validation_errors:
                self.logger.error(f"Configuration validation failed: {validation_errors}")
                return False
            
            profile = ConfigProfile(name, description, config)
            self.profiles[name] = profile
            self._save_profiles()
            
            self.logger.info(f"Created configuration profile: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating profile: {e}")
            return False

    def get_profile(self, name: str) -> Optional[ConfigProfile]:
        """Get a configuration profile by name."""
        profile = self.profiles.get(name)
        if profile:
            profile.last_used = datetime.now()
            self._save_profiles()
        return profile

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all available configuration profiles."""
        return [
            {
                'name': profile.name,
                'description': profile.description,
                'created_at': profile.created_at,
                'last_used': profile.last_used
            }
            for profile in self.profiles.values()
        ]

    def delete_profile(self, name: str) -> bool:
        """Delete a configuration profile."""
        if name in self.profiles:
            del self.profiles[name]
            self._save_profiles()
            self.logger.info(f"Deleted configuration profile: {name}")
            return True
        return False

    def update_profile(self, name: str, description: str = None, 
                      config: Dict[str, Any] = None) -> bool:
        """Update an existing configuration profile."""
        try:
            if name not in self.profiles:
                return False
            
            profile = self.profiles[name]
            
            if description:
                profile.description = description
            
            if config:
                validation_errors = self.validate_config(config)
                if validation_errors:
                    self.logger.error(f"Configuration validation failed: {validation_errors}")
                    return False
                profile.config = config
            
            self._save_profiles()
            self.logger.info(f"Updated configuration profile: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating profile: {e}")
            return False

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate configuration against rules."""
        errors = []
        
        for key, value in config.items():
            if key in self.validation_rules:
                rule = self.validation_rules[key]
                
                # Type validation
                expected_type = rule['type']
                if not isinstance(value, expected_type):
                    errors.append(f"{key}: Expected {expected_type.__name__}, got {type(value).__name__}")
                    continue
                
                # Range validation for numbers
                if expected_type in [int, float]:
                    if 'min' in rule and value < rule['min']:
                        errors.append(f"{key}: Value {value} is below minimum {rule['min']}")
                    if 'max' in rule and value > rule['max']:
                        errors.append(f"{key}: Value {value} is above maximum {rule['max']}")
                
                # Length validation for strings
                if expected_type == str:
                    if 'min_length' in rule and len(value) < rule['min_length']:
                        errors.append(f"{key}: String length {len(value)} is below minimum {rule['min_length']}")
                    if 'max_length' in rule and len(value) > rule['max_length']:
                        errors.append(f"{key}: String length {len(value)} is above maximum {rule['max_length']}")
        
        return errors

    def get_module_config(self, module_name: str, profile_name: str = None) -> Dict[str, Any]:
        """Get configuration for a specific module."""
        base_config = {
            'timeout': 30,
            'threads': 10,
            'rate_limit': 0.5,
            'user_agent': 'ReconToolKit/1.0',
            'max_redirects': 5
        }
        
        # Apply profile configuration if specified
        if profile_name:
            profile = self.get_profile(profile_name)
            if profile:
                base_config.update(profile.config)
        
        # Apply module-specific overrides
        module_config_key = f"module_{module_name}_config"
        module_overrides = self.db_manager.get_config(module_config_key)
        if module_overrides:
            try:
                overrides = json.loads(module_overrides)
                base_config.update(overrides)
            except json.JSONDecodeError:
                pass
        
        return base_config

    def set_module_config(self, module_name: str, config: Dict[str, Any]) -> bool:
        """Set configuration for a specific module."""
        try:
            validation_errors = self.validate_config(config)
            if validation_errors:
                self.logger.error(f"Module configuration validation failed: {validation_errors}")
                return False
            
            module_config_key = f"module_{module_name}_config"
            self.db_manager.set_config(module_config_key, json.dumps(config))
            
            self.logger.info(f"Updated configuration for module: {module_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting module configuration: {e}")
            return False

    def export_profile(self, profile_name: str, file_path: str) -> bool:
        """Export a configuration profile to file."""
        try:
            profile = self.profiles.get(profile_name)
            if not profile:
                return False
            
            export_data = {
                'profile': profile.to_dict(),
                'exported_at': datetime.now().isoformat(),
                'tool_version': '1.0.0'
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Exported profile {profile_name} to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting profile: {e}")
            return False

    def import_profile(self, file_path: str) -> bool:
        """Import a configuration profile from file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            profile_data = import_data['profile']
            profile = ConfigProfile.from_dict(profile_data)
            
            # Check if profile already exists
            if profile.name in self.profiles:
                profile.name = f"{profile.name}_imported_{int(time.time())}"
            
            # Validate configuration
            validation_errors = self.validate_config(profile.config)
            if validation_errors:
                self.logger.error(f"Imported profile validation failed: {validation_errors}")
                return False
            
            self.profiles[profile.name] = profile
            self._save_profiles()
            
            self.logger.info(f"Imported profile: {profile.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing profile: {e}")
            return False

    def auto_tune_config(self, module_name: str, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Auto-tune configuration based on performance data."""
        current_config = self.get_module_config(module_name)
        tuned_config = current_config.copy()
        
        # Auto-tune based on performance metrics
        if 'success_rate' in performance_data:
            success_rate = performance_data['success_rate']
            
            if success_rate < 0.5:  # Low success rate
                # Reduce aggressiveness
                tuned_config['threads'] = max(1, tuned_config.get('threads', 10) // 2)
                tuned_config['rate_limit'] = min(5.0, tuned_config.get('rate_limit', 0.5) * 2)
                tuned_config['timeout'] = min(60, tuned_config.get('timeout', 30) + 10)
                
            elif success_rate > 0.9:  # High success rate
                # Increase aggressiveness
                tuned_config['threads'] = min(100, tuned_config.get('threads', 10) * 2)
                tuned_config['rate_limit'] = max(0.1, tuned_config.get('rate_limit', 0.5) / 2)
        
        if 'avg_response_time' in performance_data:
            avg_response_time = performance_data['avg_response_time']
            
            if avg_response_time > 10:  # Slow responses
                tuned_config['timeout'] = max(tuned_config.get('timeout', 30), avg_response_time * 2)
                tuned_config['rate_limit'] = max(0.5, tuned_config.get('rate_limit', 0.5))
        
        return tuned_config

    def get_optimization_suggestions(self, module_name: str) -> List[str]:
        """Get optimization suggestions for a module configuration."""
        config = self.get_module_config(module_name)
        suggestions = []
        
        # Thread optimization
        threads = config.get('threads', 10)
        if threads > 50:
            suggestions.append("Consider reducing thread count to avoid overwhelming target servers")
        elif threads < 5:
            suggestions.append("Consider increasing thread count for better performance")
        
        # Rate limiting
        rate_limit = config.get('rate_limit', 0.5)
        if rate_limit < 0.1:
            suggestions.append("Very aggressive rate limiting may trigger security controls")
        elif rate_limit > 2.0:
            suggestions.append("High rate limiting may slow down scans significantly")
        
        # Timeout settings
        timeout = config.get('timeout', 30)
        if timeout < 10:
            suggestions.append("Low timeout may cause false negatives on slow networks")
        elif timeout > 60:
            suggestions.append("High timeout may slow down scans on unresponsive targets")
        
        return suggestions

    def create_custom_wordlist_config(self, wordlist_name: str, 
                                    wordlist_path: str, category: str) -> bool:
        """Create configuration for a custom wordlist."""
        try:
            wordlist_config = {
                'name': wordlist_name,
                'path': wordlist_path,
                'category': category,
                'created_at': datetime.now().isoformat(),
                'line_count': self._count_lines(wordlist_path) if os.path.exists(wordlist_path) else 0
            }
            
            # Get existing wordlists
            existing_wordlists = self.db_manager.get_config('custom_wordlists', '{}')
            wordlists = json.loads(existing_wordlists) if existing_wordlists else {}
            
            wordlists[wordlist_name] = wordlist_config
            self.db_manager.set_config('custom_wordlists', json.dumps(wordlists))
            
            self.logger.info(f"Added custom wordlist: {wordlist_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding custom wordlist: {e}")
            return False

    def _count_lines(self, file_path: str) -> int:
        """Count lines in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def get_wordlists(self) -> List[Dict[str, Any]]:
        """Get all configured wordlists."""
        try:
            custom_wordlists = self.db_manager.get_config('custom_wordlists', '{}')
            return list(json.loads(custom_wordlists).values()) if custom_wordlists else []
        except Exception:
            return []

    def cleanup_old_profiles(self, days: int = 30) -> int:
        """Clean up old unused profiles."""
        cleaned = 0
        cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
        
        profiles_to_delete = []
        for name, profile in self.profiles.items():
            if name not in self.default_configs:  # Don't delete default profiles
                last_used = profile.last_used or profile.created_at
                if last_used.timestamp() < cutoff_date:
                    profiles_to_delete.append(name)
        
        for name in profiles_to_delete:
            self.delete_profile(name)
            cleaned += 1
        
        return cleaned
