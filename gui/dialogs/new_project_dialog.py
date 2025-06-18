"""
New Project Dialog
Dialog for creating new projects in ReconToolKit.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QMessageBox
)
from PyQt5.QtCore import Qt

from ...core.database import DatabaseManager


class NewProjectDialog(QDialog):
    """Dialog for creating new projects."""
    
    def __init__(self, db_manager: DatabaseManager, parent=None):
        """
        Initialize new project dialog.
        
        Args:
            db_manager: Database manager
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.db_manager = db_manager
        
        self.setWindowTitle("New Project")
        self.setModal(True)
        self.resize(400, 300)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        
        # Project name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Enter project name...")
        form_layout.addRow("Project Name*:", self.name_edit)
        
        # Project description
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("Enter project description (optional)...")
        self.description_edit.setMaximumHeight(100)
        form_layout.addRow("Description:", self.description_edit)
        
        layout.addLayout(form_layout)
        
        # Note
        note_label = QLabel("* Required field")
        note_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(note_label)
        
        layout.addStretch()
        
        # Button layout
        button_layout = QHBoxLayout()
        
        button_layout.addStretch()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        create_button = QPushButton("Create Project")
        create_button.clicked.connect(self._create_project)
        create_button.setDefault(True)
        button_layout.addWidget(create_button)
        
        layout.addLayout(button_layout)
    
    def _create_project(self):
        """Create the project."""
        name = self.name_edit.text().strip()
        description = self.description_edit.toPlainText().strip()
        
        if not name:
            QMessageBox.warning(self, "Validation Error", "Project name is required.")
            return
        
        # Validate name
        if len(name) < 2:
            QMessageBox.warning(self, "Validation Error", "Project name must be at least 2 characters long.")
            return
        
        if len(name) > 100:
            QMessageBox.warning(self, "Validation Error", "Project name must be less than 100 characters long.")
            return
        
        self.accept()
    
    def get_project_data(self):
        """Get the project data."""
        return {
            'name': self.name_edit.text().strip(),
            'description': self.description_edit.toPlainText().strip()
        }
