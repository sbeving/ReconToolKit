"""
Results Viewer Widget
Displays and manages scan results with filtering and export capabilities.
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLineEdit, QComboBox, QPushButton, QSplitter, QTextEdit, QGroupBox,
    QHeaderView, QFileDialog, QMessageBox, QLabel, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont

from ..core.database import DatabaseManager
from ..core.config import ConfigManager


class ResultsViewerWidget(QWidget):
    """Widget for viewing and managing scan results."""
    
    results_updated = pyqtSignal()
    
    def __init__(self, db_manager: DatabaseManager, config_manager: ConfigManager):
        """
        Initialize results viewer widget.
        
        Args:
            db_manager: Database manager
            config_manager: Configuration manager
        """
        super().__init__()
        
        self.db_manager = db_manager
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        self.current_scan_data = None
        
        self._init_ui()
        self.refresh()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with search and filters
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Title
        title_label = QLabel("Scan Results & Reports")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2196F3;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)
        
        # Search and filter controls
        controls_layout = QHBoxLayout()
        
        # Search box
        search_label = QLabel("Search:")
        controls_layout.addWidget(search_label)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search results...")
        self.search_box.textChanged.connect(self._filter_results)
        controls_layout.addWidget(self.search_box)
        
        # Module filter
        module_label = QLabel("Module:")
        controls_layout.addWidget(module_label)
        
        self.module_filter = QComboBox()
        self.module_filter.addItem("All Modules")
        self.module_filter.currentTextChanged.connect(self._filter_results)
        controls_layout.addWidget(self.module_filter)
        
        # Status filter
        status_label = QLabel("Status:")
        controls_layout.addWidget(status_label)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Completed", "Running", "Error"])
        self.status_filter.currentTextChanged.connect(self._filter_results)
        controls_layout.addWidget(self.status_filter)
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh)
        controls_layout.addWidget(refresh_button)
        
        # Export button
        export_button = QPushButton("Export Results")
        export_button.clicked.connect(self.export_results)
        controls_layout.addWidget(export_button)
        
        controls_layout.addStretch()
        
        header_layout.addLayout(controls_layout)
        layout.addWidget(header_frame)
        
        # Main content splitter
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Results table
        left_panel = self._create_results_table()
        splitter.addWidget(left_panel)
        
        # Right panel - Result details
        right_panel = self._create_details_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([600, 400])
    
    def _create_results_table(self) -> QWidget:
        """Create the results table."""
        group = QGroupBox("Scan Results")
        layout = QVBoxLayout(group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        
        # Table headers
        headers = ["ID", "Module", "Target", "Status", "Started", "Results Count"]
        self.results_table.setColumnCount(len(headers))
        self.results_table.setHorizontalHeaderLabels(headers)
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # ID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Module
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Target
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Started
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Results Count
        
        # Connect selection signal
        self.results_table.itemSelectionChanged.connect(self._on_result_selected)
        
        layout.addWidget(self.results_table)
        
        return group
    
    def _create_details_panel(self) -> QWidget:
        """Create the details panel."""
        group = QGroupBox("Result Details")
        layout = QVBoxLayout(group)
        
        # Details text area
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 9))
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
                border-radius: 3px;
            }
        """)
        
        layout.addWidget(self.details_text)
        
        # Action buttons for selected result
        button_layout = QHBoxLayout()
        
        self.export_selected_button = QPushButton("Export Selected")
        self.export_selected_button.setEnabled(False)
        self.export_selected_button.clicked.connect(self._export_selected)
        button_layout.addWidget(self.export_selected_button)
        
        self.delete_selected_button = QPushButton("Delete Selected")
        self.delete_selected_button.setEnabled(False)
        self.delete_selected_button.clicked.connect(self._delete_selected)
        button_layout.addWidget(self.delete_selected_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
    
    def refresh(self):
        """Refresh the results display."""
        try:
            # Get all scans with their project information
            import sqlite3
            
            with sqlite3.connect(self.db_manager.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT s.*, p.name as project_name,
                           (SELECT COUNT(*) FROM results_summary rs WHERE rs.scan_id = s.id) as result_count
                    FROM scans s
                    LEFT JOIN projects p ON s.project_id = p.id
                    ORDER BY s.started_at DESC
                """)
                
                self.scan_data = [dict(row) for row in cursor.fetchall()]
            
            # Update module filter
            self._update_module_filter()
            
            # Populate table
            self._populate_results_table()
            
            # Emit signal
            self.results_updated.emit()
            
        except Exception as e:
            self.logger.error(f"Error refreshing results: {e}")
    
    def _update_module_filter(self):
        """Update the module filter dropdown."""
        current_text = self.module_filter.currentText()
        
        # Get unique module names
        modules = set()
        for scan in self.scan_data:
            if scan['module_name']:
                modules.add(scan['module_name'])
        
        # Update filter
        self.module_filter.clear()
        self.module_filter.addItem("All Modules")
        for module in sorted(modules):
            self.module_filter.addItem(module)
        
        # Restore selection if possible
        index = self.module_filter.findText(current_text)
        if index >= 0:
            self.module_filter.setCurrentIndex(index)
    
    def _populate_results_table(self):
        """Populate the results table."""
        filtered_data = self._get_filtered_data()
        
        self.results_table.setRowCount(len(filtered_data))
        
        for row, scan in enumerate(filtered_data):
            # ID
            id_item = QTableWidgetItem(str(scan['id']))
            id_item.setData(Qt.UserRole, scan)
            self.results_table.setItem(row, 0, id_item)
            
            # Module
            module_item = QTableWidgetItem(scan['module_name'] or 'Unknown')
            self.results_table.setItem(row, 1, module_item)
            
            # Target
            target_item = QTableWidgetItem(scan['target'] or 'Unknown')
            self.results_table.setItem(row, 2, target_item)
            
            # Status
            status_item = QTableWidgetItem(scan['status'] or 'Unknown')
            # Color code by status
            if scan['status'] == 'completed':
                status_item.setBackground(Qt.green)
            elif scan['status'] == 'running':
                status_item.setBackground(Qt.yellow)
            elif scan['status'] == 'error':
                status_item.setBackground(Qt.red)
            self.results_table.setItem(row, 3, status_item)
            
            # Started time
            started_time = 'Unknown'
            if scan['started_at']:
                try:
                    dt = datetime.fromisoformat(scan['started_at'].replace('Z', '+00:00'))
                    started_time = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    started_time = scan['started_at']
            
            time_item = QTableWidgetItem(started_time)
            self.results_table.setItem(row, 4, time_item)
            
            # Results count
            count_item = QTableWidgetItem(str(scan.get('result_count', 0)))
            self.results_table.setItem(row, 5, count_item)
    
    def _get_filtered_data(self) -> List[Dict[str, Any]]:
        """Get filtered scan data based on current filters."""
        filtered_data = []
        
        search_text = self.search_box.text().lower()
        module_filter = self.module_filter.currentText()
        status_filter = self.status_filter.currentText()
        
        for scan in self.scan_data:
            # Apply search filter
            if search_text:
                searchable_text = f"{scan.get('module_name', '')} {scan.get('target', '')} {scan.get('project_name', '')}".lower()
                if search_text not in searchable_text:
                    continue
            
            # Apply module filter
            if module_filter != "All Modules" and scan.get('module_name') != module_filter:
                continue
            
            # Apply status filter
            if status_filter != "All" and scan.get('status') != status_filter.lower():
                continue
            
            filtered_data.append(scan)
        
        return filtered_data
    
    def _filter_results(self):
        """Apply filters to the results table."""
        self._populate_results_table()
    
    def _on_result_selected(self):
        """Handle result selection."""
        selected_rows = self.results_table.selectionModel().selectedRows()
        
        if selected_rows:
            row = selected_rows[0].row()
            id_item = self.results_table.item(row, 0)
            scan_data = id_item.data(Qt.UserRole)
            
            self.current_scan_data = scan_data
            self._display_scan_details(scan_data)
            
            # Enable action buttons
            self.export_selected_button.setEnabled(True)
            self.delete_selected_button.setEnabled(True)
        else:
            self.current_scan_data = None
            self.details_text.clear()
            
            # Disable action buttons
            self.export_selected_button.setEnabled(False)
            self.delete_selected_button.setEnabled(False)
    
    def _display_scan_details(self, scan_data: Dict[str, Any]):
        """Display detailed information about a scan."""
        self.details_text.clear()
        
        # Basic information
        self.details_text.append("SCAN INFORMATION")
        self.details_text.append("=" * 40)
        self.details_text.append(f"ID: {scan_data['id']}")
        self.details_text.append(f"Module: {scan_data['module_name']}")
        self.details_text.append(f"Target: {scan_data['target']}")
        self.details_text.append(f"Status: {scan_data['status']}")
        self.details_text.append(f"Project: {scan_data.get('project_name', 'Unknown')}")
        self.details_text.append(f"Started: {scan_data['started_at']}")
        if scan_data['completed_at']:
            self.details_text.append(f"Completed: {scan_data['completed_at']}")
        
        # Results
        if scan_data['results']:
            try:
                results = json.loads(scan_data['results'])
                self.details_text.append("\nRESULTS")
                self.details_text.append("=" * 40)
                self.details_text.append(json.dumps(results, indent=2))
            except Exception as e:
                self.details_text.append(f"\nError parsing results: {e}")
                self.details_text.append(scan_data['results'])
        else:
            self.details_text.append("\nNo results available")
    
    def export_results(self):
        """Export all results to a file."""
        try:
            file_path, file_filter = QFileDialog.getSaveFileName(
                self, "Export Results", 
                f"recontoolkit_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;HTML Files (*.html);;CSV Files (*.csv)"
            )
            
            if not file_path:
                return
            
            if file_filter.startswith("JSON"):
                self._export_json(file_path, self.scan_data)
            elif file_filter.startswith("HTML"):
                self._export_html(file_path, self.scan_data)
            elif file_filter.startswith("CSV"):
                self._export_csv(file_path, self.scan_data)
            
            QMessageBox.information(self, "Export Complete", f"Results exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Export error: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
    
    def _export_selected(self):
        """Export selected result to a file."""
        if not self.current_scan_data:
            return
        
        try:
            file_path, file_filter = QFileDialog.getSaveFileName(
                self, "Export Selected Result", 
                f"scan_{self.current_scan_data['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;HTML Files (*.html)"
            )
            
            if not file_path:
                return
            
            if file_filter.startswith("JSON"):
                self._export_json(file_path, [self.current_scan_data])
            elif file_filter.startswith("HTML"):
                self._export_html(file_path, [self.current_scan_data])
            
            QMessageBox.information(self, "Export Complete", f"Result exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Export error: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to export result: {str(e)}")
    
    def _export_json(self, file_path: str, data: List[Dict[str, Any]]):
        """Export data to JSON format."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'tool': 'ReconToolKit v1.0.0',
            'scan_count': len(data),
            'scans': []
        }
        
        for scan in data:
            scan_export = scan.copy()
            # Parse results JSON if present
            if scan_export.get('results'):
                try:
                    scan_export['results'] = json.loads(scan_export['results'])
                except:
                    pass  # Keep as string if parsing fails
            
            export_data['scans'].append(scan_export)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def _export_html(self, file_path: str, data: List[Dict[str, Any]]):
        """Export data to HTML format."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ReconToolKit Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2196F3; }}
                .scan {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
                .scan-header {{ background: #f5f5f5; padding: 10px; margin: -15px -15px 10px -15px; border-radius: 5px 5px 0 0; }}
                .status-completed {{ color: green; font-weight: bold; }}
                .status-error {{ color: red; font-weight: bold; }}
                .status-running {{ color: orange; font-weight: bold; }}
                pre {{ background: #f8f8f8; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>ReconToolKit Scan Results</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Scans: {len(data)}</p>
        """
        
        for scan in data:
            status_class = f"status-{scan.get('status', 'unknown')}"
            
            html_content += f"""
            <div class="scan">
                <div class="scan-header">
                    <h3>Scan #{scan['id']} - {scan['module_name']}</h3>
                    <p><strong>Target:</strong> {scan['target']}</p>
                    <p><strong>Status:</strong> <span class="{status_class}">{scan['status']}</span></p>
                    <p><strong>Started:</strong> {scan['started_at']}</p>
                </div>
            """
            
            if scan.get('results'):
                try:
                    results = json.loads(scan['results'])
                    html_content += f"<pre>{json.dumps(results, indent=2)}</pre>"
                except:
                    html_content += f"<pre>{scan['results']}</pre>"
            else:
                html_content += "<p>No results available</p>"
            
            html_content += "</div>"
        
        html_content += """
        </body>
        </html>
        """
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _export_csv(self, file_path: str, data: List[Dict[str, Any]]):
        """Export data to CSV format."""
        import csv
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['ID', 'Module', 'Target', 'Status', 'Project', 'Started', 'Completed', 'Result Count'])
            
            # Write data
            for scan in data:
                result_count = 0
                if scan.get('results'):
                    try:
                        results = json.loads(scan['results'])
                        # Try to count results
                        if isinstance(results, dict):
                            if 'subdomains' in results:
                                result_count = len(results['subdomains'])
                            elif 'data' in results:
                                result_count = len(results['data'])
                    except:
                        pass
                
                writer.writerow([
                    scan['id'],
                    scan['module_name'],
                    scan['target'],
                    scan['status'],
                    scan.get('project_name', ''),
                    scan['started_at'],
                    scan.get('completed_at', ''),
                    result_count
                ])
    
    def _delete_selected(self):
        """Delete selected scan result."""
        if not self.current_scan_data:
            return
        
        reply = QMessageBox.question(
            self, "Delete Scan",
            f"Are you sure you want to delete scan #{self.current_scan_data['id']}?\n"
            f"This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Delete from database
                import sqlite3
                
                with sqlite3.connect(self.db_manager.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Delete results summary entries
                    cursor.execute("DELETE FROM results_summary WHERE scan_id = ?", 
                                 (self.current_scan_data['id'],))
                    
                    # Delete scan
                    cursor.execute("DELETE FROM scans WHERE id = ?", 
                                 (self.current_scan_data['id'],))
                    
                    conn.commit()
                
                # Refresh display
                self.refresh()
                
                QMessageBox.information(self, "Deleted", "Scan result deleted successfully.")
                
            except Exception as e:
                self.logger.error(f"Error deleting scan: {e}")
                QMessageBox.critical(self, "Error", f"Failed to delete scan: {str(e)}")
