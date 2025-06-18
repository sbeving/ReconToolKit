"""
ReconToolKit Dashboard Widget
Displays project overview, recent scans, and quick statistics.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGroupBox, QGridLayout, QPushButton, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPalette

from ..core.database import DatabaseManager
from ..core.config import ConfigManager


class DashboardWidget(QWidget):
    """Dashboard widget for the main window."""
    
    project_selected = pyqtSignal(int)  # project_id
    
    def __init__(self, db_manager: DatabaseManager, config_manager: ConfigManager):
        """
        Initialize the dashboard widget.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
            config_manager (ConfigManager): Configuration manager instance
        """
        super().__init__()
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        self.config_manager = config_manager
        
        self._init_ui()
        self._setup_refresh_timer()
        self.refresh()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        
        # Statistics section
        stats_group = QGroupBox("Overview")
        stats_layout = QGridLayout(stats_group)
        
        # Project count
        self.projects_label = QLabel("0")
        self.projects_label.setAlignment(Qt.AlignCenter)
        self.projects_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                padding: 10px;
            }
        """)
        
        projects_title = QLabel("Projects")
        projects_title.setAlignment(Qt.AlignCenter)
        projects_title.setStyleSheet("font-weight: bold; color: #666;")
        
        stats_layout.addWidget(self.projects_label, 0, 0)
        stats_layout.addWidget(projects_title, 1, 0)
        
        # Scans count
        self.scans_label = QLabel("0")
        self.scans_label.setAlignment(Qt.AlignCenter)
        self.scans_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #4CAF50;
                padding: 10px;
            }
        """)
        
        scans_title = QLabel("Total Scans")
        scans_title.setAlignment(Qt.AlignCenter)
        scans_title.setStyleSheet("font-weight: bold; color: #666;")
        
        stats_layout.addWidget(self.scans_label, 0, 1)
        stats_layout.addWidget(scans_title, 1, 1)
        
        # Results count
        self.results_label = QLabel("0")
        self.results_label.setAlignment(Qt.AlignCenter)
        self.results_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #FF9800;
                padding: 10px;
            }
        """)
        
        results_title = QLabel("Results")
        results_title.setAlignment(Qt.AlignCenter)
        results_title.setStyleSheet("font-weight: bold; color: #666;")
        
        stats_layout.addWidget(self.results_label, 0, 2)
        stats_layout.addWidget(results_title, 1, 2)
        
        layout.addWidget(stats_group)
        
        # Recent projects section
        projects_group = QGroupBox("Recent Projects")
        projects_layout = QVBoxLayout(projects_group)
        
        self.projects_list = QListWidget()
        self.projects_list.setMaximumHeight(150)
        self.projects_list.itemDoubleClicked.connect(self._on_project_selected)
        projects_layout.addWidget(self.projects_list)
        
        layout.addWidget(projects_group)
        
        # Recent activity section
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_list = QListWidget()
        self.activity_list.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_list)
        
        layout.addWidget(activity_group)
        
        # System status section
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_labels = {}
        
        # Database status
        db_status_layout = QHBoxLayout()
        db_status_layout.addWidget(QLabel("Database:"))
        self.status_labels['database'] = QLabel("Connected")
        self.status_labels['database'].setStyleSheet("color: #4CAF50; font-weight: bold;")
        db_status_layout.addWidget(self.status_labels['database'])
        db_status_layout.addStretch()
        status_layout.addLayout(db_status_layout)
        
        # API keys status
        api_status_layout = QHBoxLayout()
        api_status_layout.addWidget(QLabel("API Keys:"))
        self.status_labels['api_keys'] = QLabel("0 configured")
        self.status_labels['api_keys'].setStyleSheet("color: #FF9800; font-weight: bold;")
        api_status_layout.addWidget(self.status_labels['api_keys'])
        api_status_layout.addStretch()
        status_layout.addLayout(api_status_layout)
        
        # Proxy status
        proxy_status_layout = QHBoxLayout()
        proxy_status_layout.addWidget(QLabel("Proxy:"))
        self.status_labels['proxy'] = QLabel("Disabled")
        self.status_labels['proxy'].setStyleSheet("color: #666; font-weight: bold;")
        proxy_status_layout.addWidget(self.status_labels['proxy'])
        proxy_status_layout.addStretch()
        status_layout.addLayout(proxy_status_layout)
        
        layout.addWidget(status_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
    
    def _setup_refresh_timer(self):
        """Setup auto-refresh timer."""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
    
    def refresh(self):
        """Refresh dashboard data."""
        try:
            self._update_statistics()
            self._update_projects_list()
            self._update_activity_list()
            self._update_system_status()
            
        except Exception as e:
            self.logger.error(f"Error refreshing dashboard: {e}")
    def _update_statistics(self):
        """Update overview statistics."""
        try:
            import sqlite3
            
            # Get project count
            projects = self.db_manager.get_projects()
            project_count = len(projects)
            self.projects_label.setText(str(project_count))
            
            # Get total scans count
            with sqlite3.connect(self.db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM scans")
                scan_count = cursor.fetchone()[0]
                self.scans_label.setText(str(scan_count))
                
                # Get total results count
                cursor.execute("SELECT COUNT(*) FROM results_summary")
                results_count = cursor.fetchone()[0]
                self.results_label.setText(str(results_count))
                
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def _update_projects_list(self):
        """Update recent projects list."""
        try:
            self.projects_list.clear()
            
            projects = self.db_manager.get_projects()
            
            # Show only the 5 most recent projects
            for project in projects[:5]:
                item_text = f"{project['name']}"
                if project['description']:
                    item_text += f" - {project['description'][:50]}..."
                
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, project['id'])
                
                # Add timestamp info
                created_date = datetime.fromisoformat(project['created_at'].replace('Z', '+00:00'))
                if created_date.date() == datetime.now().date():
                    time_info = f"Today {created_date.strftime('%H:%M')}"
                elif created_date.date() == (datetime.now() - timedelta(days=1)).date():
                    time_info = f"Yesterday {created_date.strftime('%H:%M')}"
                else:
                    time_info = created_date.strftime('%Y-%m-%d')
                
                item.setToolTip(f"Created: {time_info}")
                
                self.projects_list.addItem(item)
            
            if not projects:
                item = QListWidgetItem("No projects yet")
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
                self.projects_list.addItem(item)
                
        except Exception as e:
            self.logger.error(f"Error updating projects list: {e}")
    
    def _update_activity_list(self):
        """Update recent activity list."""
        try:
            import sqlite3
            
            self.activity_list.clear()
            
            # Get recent scans
            with sqlite3.connect(self.db_manager.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT s.*, p.name as project_name
                    FROM scans s
                    JOIN projects p ON s.project_id = p.id
                    ORDER BY s.started_at DESC
                    LIMIT 10
                """)
                
                scans = [dict(row) for row in cursor.fetchall()]
            
            for scan in scans:
                # Format activity text
                status_icon = "✓" if scan['status'] == 'completed' else "⏳" if scan['status'] == 'running' else "⚠"
                activity_text = f"{status_icon} {scan['module_name']} on {scan['target']}"
                
                item = QListWidgetItem(activity_text)
                
                # Add timestamp
                started_date = datetime.fromisoformat(scan['started_at'].replace('Z', '+00:00'))
                time_ago = self._format_time_ago(started_date)
                item.setToolTip(f"Project: {scan['project_name']}\nStarted: {time_ago}")
                
                # Color based on status
                if scan['status'] == 'completed':
                    item.setForeground(QPalette().color(QPalette.Text))
                elif scan['status'] == 'running':
                    item.setForeground(QPalette().color(QPalette.Highlight))
                else:
                    item.setForeground(QPalette().color(QPalette.Mid))
                
                self.activity_list.addItem(item)
            
            if not scans:
                item = QListWidgetItem("No recent activity")
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
                self.activity_list.addItem(item)
                
        except Exception as e:
            self.logger.error(f"Error updating activity list: {e}")
    
    def _update_system_status(self):
        """Update system status indicators."""
        try:
            # Database status
            try:
                # Test database connection
                projects = self.db_manager.get_projects()
                self.status_labels['database'].setText("Connected")
                self.status_labels['database'].setStyleSheet("color: #4CAF50; font-weight: bold;")
            except:
                self.status_labels['database'].setText("Error")
                self.status_labels['database'].setStyleSheet("color: #F44336; font-weight: bold;")
            
            # API keys status
            api_count = 0
            common_apis = ['virustotal', 'shodan', 'hunter', 'github']
            for api in common_apis:
                if self.config_manager.get_api_key(api):
                    api_count += 1
            
            self.status_labels['api_keys'].setText(f"{api_count} configured")
            if api_count > 0:
                self.status_labels['api_keys'].setStyleSheet("color: #4CAF50; font-weight: bold;")
            else:
                self.status_labels['api_keys'].setStyleSheet("color: #FF9800; font-weight: bold;")
            
            # Proxy status
            proxy_config = self.config_manager.get_proxy_config()
            if proxy_config['enabled'] and proxy_config['host']:
                self.status_labels['proxy'].setText("Enabled")
                self.status_labels['proxy'].setStyleSheet("color: #2196F3; font-weight: bold;")
            else:
                self.status_labels['proxy'].setText("Disabled")
                self.status_labels['proxy'].setStyleSheet("color: #666; font-weight: bold;")
                
        except Exception as e:
            self.logger.error(f"Error updating system status: {e}")
    
    def _format_time_ago(self, timestamp: datetime) -> str:
        """Format timestamp as 'time ago'."""
        now = datetime.now()
        if timestamp.tzinfo:
            now = now.replace(tzinfo=timestamp.tzinfo)
        
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    
    def _on_project_selected(self, item: QListWidgetItem):
        """Handle project selection."""
        project_id = item.data(Qt.UserRole)
        if project_id:
            self.project_selected.emit(project_id)
    
    def _get_connection(self):
        """Get database connection with proper context management."""
        return self.db_manager._get_connection()
    
    def _get_row_factory(self):
        """Get row factory for database queries."""
        import sqlite3
        return sqlite3.Row
