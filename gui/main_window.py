"""
ReconToolKit Main Window
Primary GUI interface for the application.
"""

import sys
import os
import logging
from typing import Dict, Any, Optional
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QLabel, QPushButton, QTextEdit, QMenuBar, QMenu,
    QAction, QStatusBar, QMessageBox, QApplication, QFrame,
    QScrollArea, QGroupBox, QGridLayout, QProgressBar
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QIcon, QPixmap, QPalette, QColor

from gui.dashboard import DashboardWidget
from gui.module_tabs import ModuleTabsWidget
from gui.results_viewer import ResultsViewerWidget
from gui.settings_dialog import SettingsDialog
from gui.about_dialog import AboutDialog
from core.database import DatabaseManager
from core.config import ConfigManager


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, db_manager: DatabaseManager, config_manager: ConfigManager):
        """
        Initialize the main window.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
            config_manager (ConfigManager): Configuration manager instance
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        self.config_manager = config_manager
        
        self.setWindowTitle("ReconToolKit v1.0.0 - OSINT & Reconnaissance Platform")
        self.setMinimumSize(1000, 700)
        
        # Load window geometry from config
        width = self.config_manager.get('window_width', 1200)
        height = self.config_manager.get('window_height', 800)
        self.resize(width, height)
        
        # Initialize UI
        self._init_ui()
        self._setup_styling()
        self._create_menu_bar()
        self._create_status_bar()
        self._connect_signals()
        
        # Show disclaimer on first run
        self._show_disclaimer_if_needed()
        
        self.logger.info("Main window initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # Create main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(main_splitter)
        
        # Left panel - Dashboard and quick actions
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel - Main content area
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        main_splitter.setSizes([300, 900])
        main_splitter.setStretchFactor(0, 0)
        main_splitter.setStretchFactor(1, 1)
    
    def _create_left_panel(self) -> QWidget:
        """Create the left panel with dashboard and quick actions."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        panel.setMinimumWidth(280)
        panel.setMaximumWidth(350)
        
        layout = QVBoxLayout(panel)
        
        # Logo and title
        title_frame = QFrame()
        title_layout = QVBoxLayout(title_frame)
        
        title_label = QLabel("ReconToolKit")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                padding: 10px;
            }
        """)
        title_layout.addWidget(title_label)
        
        subtitle_label = QLabel("OSINT & Reconnaissance Platform")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #666;
                padding-bottom: 10px;
            }
        """)
        title_layout.addWidget(subtitle_label)
        
        layout.addWidget(title_frame)
        
        # Dashboard widget
        self.dashboard = DashboardWidget(self.db_manager, self.config_manager)
        layout.addWidget(self.dashboard)
        
        # Quick actions
        quick_actions_group = QGroupBox("Quick Actions")
        quick_actions_layout = QVBoxLayout(quick_actions_group)
        
        # New project button
        new_project_btn = QPushButton("New Project")
        new_project_btn.clicked.connect(self._new_project)
        quick_actions_layout.addWidget(new_project_btn)
        
        # Settings button
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self._open_settings)
        quick_actions_layout.addWidget(settings_btn)
        
        # Help button
        help_btn = QPushButton("Help & About")
        help_btn.clicked.connect(self._show_about)
        quick_actions_layout.addWidget(help_btn)
        
        layout.addWidget(quick_actions_group)
        
        # Status information
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        layout.addWidget(status_group)
        
        # Stretch to push everything to the top
        layout.addStretch()
        
        return panel
    
    def _create_right_panel(self) -> QWidget:
        """Create the right panel with main content tabs."""
        # Main tab widget
        self.main_tabs = QTabWidget()
        self.main_tabs.setTabPosition(QTabWidget.North)
        self.main_tabs.setDocumentMode(True)
        
        # Module tabs (Passive OSINT, Active Recon, etc.)
        self.module_tabs = ModuleTabsWidget(self.db_manager, self.config_manager)
        self.main_tabs.addTab(self.module_tabs, "Reconnaissance Modules")
        
        # Results viewer
        self.results_viewer = ResultsViewerWidget(self.db_manager, self.config_manager)
        self.main_tabs.addTab(self.results_viewer, "Results & Reports")
        
        # Connect signals
        self.module_tabs.scan_started.connect(self._on_scan_started)
        self.module_tabs.scan_completed.connect(self._on_scan_completed)
        self.module_tabs.scan_progress.connect(self._on_scan_progress)
        
        return self.main_tabs
    
    def _setup_styling(self):
        """Setup application styling based on theme."""
        theme = self.config_manager.get('theme', 'dark')
        
        if theme == 'dark':
            self._apply_dark_theme()
        else:
            self._apply_light_theme()
    
    def _apply_dark_theme(self):
        """Apply dark theme styling."""
        dark_style = """
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            
            QFrame {
                background-color: #3c3c3c;
                border: 1px solid #555;
                border-radius: 5px;
            }
            
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #3c3c3c;
            }
            
            QTabBar::tab {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: #3c3c3c;
                border-bottom: 2px solid #2196F3;
            }
            
            QTabBar::tab:hover {
                background-color: #4a4a4a;
            }
            
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #1976D2;
            }
            
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            
            QPushButton:disabled {
                background-color: #555;
                color: #999;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #2196F3;
            }
            
            QTextEdit, QLineEdit {
                background-color: #404040;
                border: 1px solid #666;
                border-radius: 3px;
                padding: 4px;
                color: #ffffff;
            }
            
            QTextEdit:focus, QLineEdit:focus {
                border: 2px solid #2196F3;
            }
            
            QProgressBar {
                border: 1px solid #666;
                border-radius: 3px;
                text-align: center;
                background-color: #404040;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 2px;
            }
            
            QMenuBar {
                background-color: #2b2b2b;
                color: #ffffff;
                border-bottom: 1px solid #555;
            }
            
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 8px;
            }
            
            QMenuBar::item:selected {
                background-color: #3c3c3c;
            }
            
            QMenu {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555;
            }
            
            QMenu::item:selected {
                background-color: #2196F3;
            }
            
            QStatusBar {
                background-color: #2b2b2b;
                color: #ffffff;
                border-top: 1px solid #555;
            }
        """
        
        self.setStyleSheet(dark_style)
    
    def _apply_light_theme(self):
        """Apply light theme styling."""
        light_style = """
            QMainWindow {
                background-color: #f5f5f5;
                color: #333333;
            }
            
            QFrame {
                background-color: #ffffff;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #1976D2;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #2196F3;
            }
        """
        
        self.setStyleSheet(light_style)
    
    def _create_menu_bar(self):
        """Create the application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        new_project_action = QAction('New Project', self)
        new_project_action.setShortcut('Ctrl+N')
        new_project_action.triggered.connect(self._new_project)
        file_menu.addAction(new_project_action)
        
        file_menu.addSeparator()
        
        export_action = QAction('Export Results', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self._export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        settings_action = QAction('Settings', self)
        settings_action.setShortcut('Ctrl+,')
        settings_action.triggered.connect(self._open_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
        disclaimer_action = QAction('Ethical Use Disclaimer', self)
        disclaimer_action.triggered.connect(self._show_disclaimer)
        help_menu.addAction(disclaimer_action)
    
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Default status message
        self.status_bar.showMessage("Ready - ReconToolKit v1.0.0")
        
        # Add permanent widgets to status bar
        self.connection_status = QLabel("Database: Connected")
        self.connection_status.setStyleSheet("color: #4CAF50;")
        self.status_bar.addPermanentWidget(self.connection_status)
    
    def _connect_signals(self):
        """Connect internal signals."""
        # Update dashboard when results change
        self.results_viewer.results_updated.connect(self.dashboard.refresh)
    
    def _show_disclaimer_if_needed(self):
        """Show ethical use disclaimer on first run."""
        if not self.config_manager.get('disclaimer_shown', False):
            self._show_disclaimer()
            self.config_manager.set('disclaimer_shown', True)
    
    def _show_disclaimer(self):
        """Show ethical use disclaimer."""
        disclaimer_text = """
<h2>ETHICAL USE DISCLAIMER</h2>

<p><b>ReconToolKit is designed for ethical hacking, educational purposes, and legitimate security assessments only.</b></p>

<p><b>By using this tool, you agree to:</b></p>
<ul>
<li>Only use this tool on systems you own or have explicit written permission to test</li>
<li>Comply with all applicable laws and regulations in your jurisdiction</li>
<li>Use the information gathered responsibly and ethically</li>
<li>Not use this tool for malicious purposes or unauthorized access</li>
<li>Respect the privacy and security of others</li>
</ul>

<p><b>IMPORTANT:</b> Unauthorized reconnaissance, scanning, or information gathering may be illegal in your jurisdiction. Always ensure you have proper authorization before using any reconnaissance tools.</p>

<p><b>The developers of ReconToolKit are not responsible for any misuse of this tool.</b></p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Ethical Use Disclaimer")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(disclaimer_text)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()
    
    def _new_project(self):
        """Create a new project."""
        from .dialogs.new_project_dialog import NewProjectDialog
        
        dialog = NewProjectDialog(self.db_manager, self)
        if dialog.exec_() == dialog.Accepted:
            project_data = dialog.get_project_data()
            try:
                project_id = self.db_manager.create_project(
                    project_data['name'],
                    project_data['description']
                )
                self.status_bar.showMessage(f"Created new project: {project_data['name']}")
                self.dashboard.refresh()
                
            except ValueError as e:
                QMessageBox.warning(self, "Error", str(e))
    
    def _open_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self.config_manager, self)
        if dialog.exec_() == dialog.Accepted:
            # Refresh styling if theme changed
            self._setup_styling()
            self.status_bar.showMessage("Settings updated")
    
    def _show_about(self):
        """Show about dialog."""
        dialog = AboutDialog(self)
        dialog.exec_()
    
    def _export_results(self):
        """Export results to file."""
        # This will be implemented in the results viewer
        self.results_viewer.export_results()
    
    @pyqtSlot(str, str)
    def _on_scan_started(self, module_name: str, target: str):
        """Handle scan started signal."""
        self.status_label.setText("Scanning...")
        self.status_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.status_bar.showMessage(f"Running {module_name} on {target}")
        
        self.logger.info(f"Scan started: {module_name} -> {target}")
    
    @pyqtSlot(str, dict)
    def _on_scan_completed(self, module_name: str, results: dict):
        """Handle scan completed signal."""
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.progress_bar.setVisible(False)
        
        result_count = len(results.get('data', []))
        self.status_bar.showMessage(f"Scan completed: {result_count} results found")
        
        # Refresh dashboard and results
        self.dashboard.refresh()
        self.results_viewer.refresh()
        
        self.logger.info(f"Scan completed: {module_name} - {result_count} results")
    
    @pyqtSlot(str, int)
    def _on_scan_progress(self, message: str, progress: int):
        """Handle scan progress signal."""
        self.status_bar.showMessage(message)
        if progress >= 0:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(progress)
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Save window geometry
        self.config_manager.set('window_width', self.width())
        self.config_manager.set('window_height', self.height())
        
        # Graceful shutdown
        self.logger.info("ReconToolKit shutting down")
        event.accept()
