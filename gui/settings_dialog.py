"""
Settings Dialog
Configuration interface for ReconToolKit.
"""

import logging
from typing import Dict, Any
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel,
    QLineEdit, QCheckBox, QSpinBox, QComboBox, QPushButton, QGroupBox,
    QFormLayout, QMessageBox, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from ..core.config import ConfigManager


class SettingsDialog(QDialog):
    """Settings configuration dialog."""
    
    def __init__(self, config_manager: ConfigManager, parent=None):
        """
        Initialize settings dialog.
        
        Args:
            config_manager: Configuration manager
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        self.setWindowTitle("ReconToolKit Settings")
        self.setModal(True)
        self.resize(600, 500)
        
        self._init_ui()
        self._load_settings()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self._create_general_tab()
        self._create_network_tab()
        self._create_api_keys_tab()
        self._create_advanced_tab()
        
        # Button layout
        button_layout = QHBoxLayout()
        
        button_layout.addStretch()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        save_button = QPushButton("Save")
        save_button.clicked.connect(self._save_settings)
        save_button.setDefault(True)
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
    
    def _create_general_tab(self):
        """Create general settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Appearance group
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout(appearance_group)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        appearance_layout.addRow("Theme:", self.theme_combo)
        
        layout.addWidget(appearance_group)
        
        # Performance group
        performance_group = QGroupBox("Performance")
        performance_layout = QFormLayout(performance_group)
        
        self.max_threads_spin = QSpinBox()
        self.max_threads_spin.setRange(1, 100)
        performance_layout.addRow("Max Threads:", self.max_threads_spin)
        
        layout.addWidget(performance_group)
        
        # Other settings
        other_group = QGroupBox("Other")
        other_layout = QFormLayout(other_group)
        
        self.auto_save_check = QCheckBox()
        other_layout.addRow("Auto-save Results:", self.auto_save_check)
        
        self.show_progress_check = QCheckBox()
        other_layout.addRow("Show Progress Details:", self.show_progress_check)
        
        layout.addWidget(other_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(tab, "General")
    
    def _create_network_tab(self):
        """Create network settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # HTTP settings group
        http_group = QGroupBox("HTTP Settings")
        http_layout = QFormLayout(http_group)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setSuffix(" seconds")
        http_layout.addRow("Request Timeout:", self.timeout_spin)
        
        self.user_agent_edit = QLineEdit()
        http_layout.addRow("User Agent:", self.user_agent_edit)
        
        layout.addWidget(http_group)
        
        # Proxy settings group
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QFormLayout(proxy_group)
        
        self.proxy_enabled_check = QCheckBox()
        self.proxy_enabled_check.toggled.connect(self._on_proxy_enabled_changed)
        proxy_layout.addRow("Enable Proxy:", self.proxy_enabled_check)
        
        self.proxy_host_edit = QLineEdit()
        proxy_layout.addRow("Proxy Host:", self.proxy_host_edit)
        
        self.proxy_port_spin = QSpinBox()
        self.proxy_port_spin.setRange(1, 65535)
        proxy_layout.addRow("Proxy Port:", self.proxy_port_spin)
        
        self.proxy_username_edit = QLineEdit()
        proxy_layout.addRow("Username:", self.proxy_username_edit)
        
        self.proxy_password_edit = QLineEdit()
        self.proxy_password_edit.setEchoMode(QLineEdit.Password)
        proxy_layout.addRow("Password:", self.proxy_password_edit)
        
        layout.addWidget(proxy_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(tab, "Network")
    
    def _create_api_keys_tab(self):
        """Create API keys tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Warning
        warning_label = QLabel(
            "API keys are stored encrypted. Only enter keys for services you plan to use."
        )
        warning_label.setStyleSheet("color: #FF9800; font-weight: bold; padding: 10px;")
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)
        
        # API keys group
        api_group = QGroupBox("API Keys")
        api_layout = QFormLayout(api_group)
        
        # Common API services
        self.api_keys = {}
        
        services = [
            ("virustotal", "VirusTotal"),
            ("shodan", "Shodan"),
            ("hunter", "Hunter.io"),
            ("github", "GitHub"),
            ("censys", "Censys"),
            ("securitytrails", "SecurityTrails")
        ]
        
        for service_id, service_name in services:
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.Password)
            edit.setPlaceholderText(f"Enter {service_name} API key...")
            self.api_keys[service_id] = edit
            api_layout.addRow(f"{service_name}:", edit)
        
        layout.addWidget(api_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(tab, "API Keys")
    
    def _create_advanced_tab(self):
        """Create advanced settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Logging group
        logging_group = QGroupBox("Logging")
        logging_layout = QFormLayout(logging_group)
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        logging_layout.addRow("Log Level:", self.log_level_combo)
        
        layout.addWidget(logging_group)
        
        # Wordlists group
        wordlist_group = QGroupBox("Wordlists")
        wordlist_layout = QFormLayout(wordlist_group)
        
        self.default_wordlist_edit = QLineEdit()
        wordlist_browse_button = QPushButton("Browse...")
        wordlist_browse_button.clicked.connect(self._browse_wordlist)
        
        wordlist_row_layout = QHBoxLayout()
        wordlist_row_layout.addWidget(self.default_wordlist_edit)
        wordlist_row_layout.addWidget(wordlist_browse_button)
        
        wordlist_widget = QWidget()
        wordlist_widget.setLayout(wordlist_row_layout)
        
        wordlist_layout.addRow("Default Subdomain Wordlist:", wordlist_widget)
        
        layout.addWidget(wordlist_group)
        
        # Reset button
        reset_button = QPushButton("Reset to Defaults")
        reset_button.clicked.connect(self._reset_to_defaults)
        layout.addWidget(reset_button)
        
        layout.addStretch()
        
        self.tab_widget.addTab(tab, "Advanced")
    
    def _load_settings(self):
        """Load current settings into the dialog."""
        # General settings
        self.theme_combo.setCurrentText(self.config_manager.get('theme', 'dark'))
        self.max_threads_spin.setValue(self.config_manager.get('max_threads', 10))
        self.auto_save_check.setChecked(self.config_manager.get('auto_save_results', True))
        self.show_progress_check.setChecked(self.config_manager.get('show_progress_details', True))
        
        # Network settings
        self.timeout_spin.setValue(self.config_manager.get('request_timeout', 30))
        self.user_agent_edit.setText(self.config_manager.get('user_agent', 'ReconToolKit/1.0.0'))
        
        # Proxy settings
        proxy_enabled = self.config_manager.get('proxy_enabled', False)
        self.proxy_enabled_check.setChecked(proxy_enabled)
        self.proxy_host_edit.setText(self.config_manager.get('proxy_host', ''))
        self.proxy_port_spin.setValue(int(self.config_manager.get('proxy_port', 8080)))
        self.proxy_username_edit.setText(self.config_manager.get('proxy_username', ''))
        self.proxy_password_edit.setText(self.config_manager.get('proxy_password', ''))
        
        self._on_proxy_enabled_changed(proxy_enabled)
        
        # API keys
        for service_id, edit in self.api_keys.items():
            api_key = self.config_manager.get_api_key(service_id)
            if api_key:
                edit.setText(api_key)
        
        # Advanced settings
        self.log_level_combo.setCurrentText(self.config_manager.get('log_level', 'INFO'))
        self.default_wordlist_edit.setText(self.config_manager.get('default_wordlist', ''))
    
    def _save_settings(self):
        """Save settings and close dialog."""
        try:
            # Validate settings
            issues = self._validate_settings()
            if issues:
                QMessageBox.warning(self, "Validation Error", "\n".join(issues))
                return
            
            # General settings
            self.config_manager.set('theme', self.theme_combo.currentText())
            self.config_manager.set('max_threads', self.max_threads_spin.value())
            self.config_manager.set('auto_save_results', self.auto_save_check.isChecked())
            self.config_manager.set('show_progress_details', self.show_progress_check.isChecked())
            
            # Network settings
            self.config_manager.set('request_timeout', self.timeout_spin.value())
            self.config_manager.set('user_agent', self.user_agent_edit.text().strip())
            
            # Proxy settings
            self.config_manager.set('proxy_enabled', self.proxy_enabled_check.isChecked())
            self.config_manager.set('proxy_host', self.proxy_host_edit.text().strip())
            self.config_manager.set('proxy_port', str(self.proxy_port_spin.value()))
            self.config_manager.set('proxy_username', self.proxy_username_edit.text().strip())
            
            proxy_password = self.proxy_password_edit.text().strip()
            if proxy_password:
                self.config_manager.set('proxy_password', proxy_password, encrypted=True)
            
            # API keys
            for service_id, edit in self.api_keys.items():
                api_key = edit.text().strip()
                if api_key:
                    self.config_manager.set_api_key(service_id, api_key)
            
            # Advanced settings
            self.config_manager.set('log_level', self.log_level_combo.currentText())
            self.config_manager.set('default_wordlist', self.default_wordlist_edit.text().strip())
            
            self.accept()
            
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
    
    def _validate_settings(self) -> list:
        """Validate current settings."""
        issues = []
        
        # Validate proxy settings if enabled
        if self.proxy_enabled_check.isChecked():
            if not self.proxy_host_edit.text().strip():
                issues.append("Proxy host is required when proxy is enabled")
            
            if not (1 <= self.proxy_port_spin.value() <= 65535):
                issues.append("Proxy port must be between 1 and 65535")
        
        # Validate user agent
        if not self.user_agent_edit.text().strip():
            issues.append("User agent cannot be empty")
        
        return issues
    
    def _on_proxy_enabled_changed(self, enabled: bool):
        """Handle proxy enabled checkbox change."""
        self.proxy_host_edit.setEnabled(enabled)
        self.proxy_port_spin.setEnabled(enabled)
        self.proxy_username_edit.setEnabled(enabled)
        self.proxy_password_edit.setEnabled(enabled)
    
    def _browse_wordlist(self):
        """Browse for wordlist file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.default_wordlist_edit.setText(file_path)
    
    def _reset_to_defaults(self):
        """Reset all settings to defaults."""
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                self.config_manager.reset_to_defaults()
                self._load_settings()
                QMessageBox.information(self, "Reset Complete", "Settings have been reset to defaults.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reset settings: {str(e)}")
