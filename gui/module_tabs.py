"""
Module Tabs Widget
Displays reconnaissance modules organized by category.
"""

import logging
from typing import Dict, Any, List, Optional
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QPushButton,
    QTextEdit, QLineEdit, QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QGridLayout, QProgressBar, QSplitter, QScrollArea, QFrame, QFormLayout,
    QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont

from core.database import DatabaseManager
from core.config import ConfigManager
from modules.passive.domain_enumeration import DomainEnumerationModule
from modules.passive.email_intelligence import EmailIntelligenceModule
from modules.passive.social_engineering_intel import SocialEngineeringIntelModule
from modules.active.port_scanner import PortScannerModule
from modules.active.web_directory_enum import WebDirectoryEnumerationModule
from modules.active.web_fuzzer import WebFuzzerModule
from modules.active.vulnerability_scanner import VulnerabilityScanner
from modules.active.ssl_tls_analyzer import SSLTLSAnalyzer
from modules.active.network_discovery import NetworkDiscoveryModule
from modules.active.advanced_web_crawler import AdvancedWebCrawlerModule
from modules.utilities.data_analyzer import DataAnalyzerModule
from modules.utilities.session_manager import SessionManagerModule
from modules.utilities.intelligence_aggregator import IntelligenceAggregatorModule
from modules.utilities.api_integration import APIIntegrationModule
from modules.utilities.advanced_report_generator import AdvancedReportGeneratorModule
from modules.utilities.threat_modeling_simple import ThreatModelingModule
from modules.utilities.continuous_monitoring_simple import ContinuousMonitoringModule


class ModuleWidget(QWidget):
    """Widget for a single reconnaissance module."""
    
    scan_started = pyqtSignal(str, str)  # module_name, target
    scan_completed = pyqtSignal(str, dict)  # module_name, results
    scan_progress = pyqtSignal(str, int)  # message, percentage
    
    def __init__(self, module, db_manager: DatabaseManager, config_manager: ConfigManager):
        """
        Initialize module widget.
        
        Args:
            module: Module instance
            db_manager: Database manager
            config_manager: Configuration manager
        """
        super().__init__()
        
        self.module = module
        self.db_manager = db_manager
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        self.current_scan_id = None
        self.input_widgets = {}
        
        self._init_ui()
        self._connect_signals()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Module header
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Module title
        title_label = QLabel(self.module.name)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2196F3;
                padding: 5px;
            }
        """)
        header_layout.addWidget(title_label)
        
        # Module description
        desc_label = QLabel(self.module.description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #666; padding: 5px;")
        header_layout.addWidget(desc_label)
        
        layout.addWidget(header_frame)
        
        # Create main splitter
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Input fields
        left_panel = self._create_input_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Output
        right_panel = self._create_output_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([400, 600])
    
    def _create_input_panel(self) -> QWidget:
        """Create input panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        panel.setMinimumWidth(350)
        panel.setMaximumWidth(450)
        
        layout = QVBoxLayout(panel)
        
        # Input fields group
        input_group = QGroupBox("Input Parameters")
        input_layout = QFormLayout(input_group)
        
        # Create input fields based on module definition
        for field in self.module.get_input_fields():
            widget = self._create_input_widget(field)
            self.input_widgets[field['name']] = widget
            
            label = QLabel(field['label'])
            if field.get('required', False):
                label.setText(f"{field['label']} *")
                label.setStyleSheet("font-weight: bold;")
            
            # Add tooltip if available
            if field.get('tooltip'):
                label.setToolTip(field['tooltip'])
                widget.setToolTip(field['tooltip'])
            
            input_layout.addRow(label, widget)
        
        layout.addWidget(input_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.run_button = QPushButton("Run Scan")
        self.run_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.run_button.clicked.connect(self._run_scan)
        button_layout.addWidget(self.run_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        self.stop_button.clicked.connect(self._stop_scan)
        button_layout.addWidget(self.stop_button)
        
        layout.addLayout(button_layout)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(progress_group)
        
        # Add stretch
        layout.addStretch()
        
        return panel
    
    def _create_output_panel(self) -> QWidget:
        """Create output panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        
        layout = QVBoxLayout(panel)
        
        # Output header
        header_layout = QHBoxLayout()
        
        output_label = QLabel("Scan Results")
        output_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(output_label)
        
        header_layout.addStretch()
        
        self.clear_button = QPushButton("Clear Output")
        self.clear_button.clicked.connect(self._clear_output)
        header_layout.addWidget(self.clear_button)
        
        layout.addLayout(header_layout)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 9))
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.output_text)
        
        return panel
    
    def _create_input_widget(self, field: Dict[str, Any]) -> QWidget:
        """Create input widget based on field definition."""
        field_type = field['type']
        
        if field_type == 'text':
            widget = QLineEdit()
            if field.get('placeholder'):
                widget.setPlaceholderText(field['placeholder'])
            if field.get('default'):
                widget.setText(str(field['default']))
            return widget
            
        elif field_type == 'checkbox':
            widget = QCheckBox()
            widget.setChecked(field.get('default', False))
            return widget
            
        elif field_type == 'combo':
            widget = QComboBox()
            options = field.get('options', [])
            widget.addItems(options)
            if field.get('default') and field['default'] in options:
                widget.setCurrentText(field['default'])
            return widget
            
        elif field_type == 'file':
            widget = QWidget()
            layout = QHBoxLayout(widget)
            layout.setContentsMargins(0, 0, 0, 0)
            
            line_edit = QLineEdit()
            browse_button = QPushButton("Browse...")
            browse_button.clicked.connect(lambda: self._browse_file(line_edit))
            
            layout.addWidget(line_edit)
            layout.addWidget(browse_button)
            
            widget.get_value = lambda: line_edit.text()
            widget.set_value = lambda x: line_edit.setText(x)
            
            return widget
            
        else:
            # Default to text input
            return QLineEdit()
    
    def _browse_file(self, line_edit: QLineEdit):
        """Browse for file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if file_path:
            line_edit.setText(file_path)
    
    def _connect_signals(self):
        """Connect module signals."""
        self.module.progress_updated.connect(self._update_progress)
        self.module.scan_completed.connect(self._scan_completed)
        self.module.scan_error.connect(self._scan_error)
    
    def _get_input_values(self) -> Dict[str, Any]:
        """Get current input values."""
        values = {}
        
        for field in self.module.get_input_fields():
            widget = self.input_widgets[field['name']]
            
            if isinstance(widget, QLineEdit):
                values[field['name']] = widget.text().strip()
            elif isinstance(widget, QCheckBox):
                values[field['name']] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                values[field['name']] = widget.currentText()
            elif hasattr(widget, 'get_value'):  # Custom widgets like file browser
                values[field['name']] = widget.get_value()
            else:
                values[field['name']] = ''
        
        return values
    
    def _run_scan(self):
        """Run the scan."""
        try:
            # Get input values
            inputs = self._get_input_values()
            
            # Get configuration
            config = {
                'request_timeout': self.config_manager.get('request_timeout', 30),
                'user_agent': self.config_manager.get('user_agent', 'ReconToolKit/1.0.0'),
                'proxy_enabled': self.config_manager.get('proxy_enabled', False),
                'proxy_host': self.config_manager.get('proxy_host', ''),
                'proxy_port': self.config_manager.get('proxy_port', ''),
            }
            
            # Create scan record in database
            # For now, we'll use a default project ID of 1
            target = inputs.get('domain', inputs.get('target', 'Unknown'))
            self.current_scan_id = self.db_manager.create_scan(
                project_id=1,  # TODO: Use actual project selection
                module_name=self.module.name,
                target=target
            )
            
            # Update UI state
            self.run_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.progress_bar.setVisible(True)
            
            # Clear previous output
            self.output_text.clear()
            self.output_text.append(f"Starting {self.module.name} scan on {target}...")
            self.output_text.append(f"Scan ID: {self.current_scan_id}")
            self.output_text.append("-" * 50)
            
            # Start scan
            self.module.start_scan(inputs, config)
            
            # Emit signal
            self.scan_started.emit(self.module.name, target)
            
        except Exception as e:
            self.logger.error(f"Error starting scan: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
            self._reset_ui_state()
    
    def _stop_scan(self):
        """Stop the running scan."""
        self.module.stop_scan()
        self._reset_ui_state()
        self.output_text.append("\n[SCAN STOPPED BY USER]")
    
    def _reset_ui_state(self):
        """Reset UI to ready state."""
        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_label.setText("Ready")
    
    @pyqtSlot(str, int)
    def _update_progress(self, message: str, percentage: int):
        """Update progress display."""
        self.progress_label.setText(message)
        
        if percentage >= 0:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(percentage)
        else:
            self.progress_bar.setRange(0, 0)  # Indeterminate
        
        # Also emit signal for main window
        self.scan_progress.emit(message, percentage)
    
    @pyqtSlot(dict)
    def _scan_completed(self, results: Dict[str, Any]):
        """Handle scan completion."""
        try:
            # Update database with results
            if self.current_scan_id:
                self.db_manager.update_scan_results(self.current_scan_id, results)
            
            # Display results
            self._display_results(results)
            
            # Reset UI
            self._reset_ui_state()
            
            # Emit signal
            self.scan_completed.emit(self.module.name, results)
            
        except Exception as e:
            self.logger.error(f"Error handling scan completion: {e}")
    
    @pyqtSlot(str)
    def _scan_error(self, error_message: str):
        """Handle scan error."""
        self.output_text.append(f"\n[ERROR] {error_message}")
        self._reset_ui_state()
        
        if self.current_scan_id:
            try:
                self.db_manager.update_scan_results(
                    self.current_scan_id, 
                    {'error': error_message}, 
                    status='error'
                )
            except Exception as e:
                self.logger.error(f"Error updating scan error in database: {e}")
    
    def _display_results(self, results: Dict[str, Any]):
        """Display scan results in the output area."""
        self.output_text.append("\n" + "=" * 50)
        self.output_text.append("SCAN RESULTS")
        self.output_text.append("=" * 50)
        
        # Display summary if available
        if 'summary' in results:
            self.output_text.append("\nSUMMARY:")
            summary = results['summary']
            for key, value in summary.items():
                self.output_text.append(f"  {key}: {value}")
        
        # Display domain-specific results
        if 'domain' in results:
            self.output_text.append(f"\nTarget Domain: {results['domain']}")
        
        if 'whois_info' in results and results['whois_info']:
            self.output_text.append("\nWHOIS INFORMATION:")
            whois_info = results['whois_info']
            for key, value in whois_info.items():
                if key != 'error':
                    self.output_text.append(f"  {key}: {value}")
        
        if 'dns_records' in results and results['dns_records']:
            self.output_text.append("\nDNS RECORDS:")
            for record_type, records in results['dns_records'].items():
                self.output_text.append(f"  {record_type}:")
                for record in records:
                    self.output_text.append(f"    {record}")
        
        if 'subdomains' in results and results['subdomains']:
            self.output_text.append(f"\nSUBDOMAINS FOUND ({len(results['subdomains'])}):")
            for subdomain_data in results['subdomains']:
                subdomain = subdomain_data['subdomain']
                method = subdomain_data.get('method', 'unknown')
                ips = subdomain_data.get('ips', [])
                ip_str = ', '.join(ips) if ips else 'No IP resolved'
                self.output_text.append(f"  {subdomain} ({method}) -> {ip_str}")
        
        if 'ip_addresses' in results and results['ip_addresses']:
            self.output_text.append(f"\nIP ADDRESSES:")
            for ip in set(results['ip_addresses']):  # Remove duplicates
                self.output_text.append(f"  {ip}")
        
        self.output_text.append("\n" + "=" * 50)
        self.output_text.append("SCAN COMPLETED")
        self.output_text.append("=" * 50)
    
    def _clear_output(self):
        """Clear the output text area."""
        self.output_text.clear()


class ModuleTabsWidget(QTabWidget):
    """Main widget containing all module tabs."""
    
    scan_started = pyqtSignal(str, str)  # module_name, target
    scan_completed = pyqtSignal(str, dict)  # module_name, results
    scan_progress = pyqtSignal(str, int)  # message, percentage
    
    def __init__(self, db_manager: DatabaseManager, config_manager: ConfigManager):
        """
        Initialize module tabs widget.
        
        Args:
            db_manager: Database manager
            config_manager: Configuration manager
        """
        super().__init__()        
        self.db_manager = db_manager
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        self._init_modules()
        self._init_ui()
    
    def _init_modules(self):
        """Initialize available modules."""
        self.modules = {
            'passive': [
                DomainEnumerationModule(),
                EmailIntelligenceModule(),
                SocialEngineeringIntelModule(),
                # Add more passive modules here
            ],
            'active': [
                PortScannerModule(),
                NetworkDiscoveryModule(),
                WebDirectoryEnumerationModule(),
                WebFuzzerModule(),
                VulnerabilityScanner(),
                SSLTLSAnalyzer(),
                AdvancedWebCrawlerModule(),
                # Add more active modules here
            ],
            'utilities': [
                DataAnalyzerModule(),
                SessionManagerModule(),
                IntelligenceAggregatorModule(),
                APIIntegrationModule(),
                AdvancedReportGeneratorModule(),
                ThreatModelingModule(),
                ContinuousMonitoringModule(),
                # Add more utility modules here
            ]
        }
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setTabPosition(QTabWidget.North)
        self.setDocumentMode(True)
        
        # Create tabs for each category
        for category, modules in self.modules.items():
            if modules:  # Only create tab if there are modules
                tab_widget = self._create_category_tab(category, modules)
                self.addTab(tab_widget, category.title())
    
    def _create_category_tab(self, category: str, modules: List) -> QWidget:
        """Create a tab for a module category."""
        tab_widget = QTabWidget()
        tab_widget.setTabPosition(QTabWidget.West)
        
        for module in modules:
            module_widget = ModuleWidget(module, self.db_manager, self.config_manager)
            
            # Connect signals
            module_widget.scan_started.connect(self.scan_started)
            module_widget.scan_completed.connect(self.scan_completed)
            module_widget.scan_progress.connect(self.scan_progress)
            
            tab_widget.addTab(module_widget, module.name)
        
        return tab_widget
