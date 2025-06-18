"""
About Dialog
Information about ReconToolKit.
"""

from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class AboutDialog(QDialog):
    """About dialog for ReconToolKit."""
    
    def __init__(self, parent=None):
        """
        Initialize about dialog.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.setWindowTitle("About ReconToolKit")
        self.setModal(True)
        self.resize(500, 400)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("ReconToolKit")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                padding: 20px;
            }
        """)
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("OSINT & Reconnaissance Platform")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #666;
                padding-bottom: 10px;
            }
        """)
        layout.addWidget(subtitle_label)
        
        # Version
        version_label = QLabel("Version 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("font-weight: bold; padding: 5px;")
        layout.addWidget(version_label)
        
        # Description
        description_text = QTextEdit()
        description_text.setReadOnly(True)
        description_text.setMaximumHeight(200)
        
        description_content = """
<h3>About ReconToolKit</h3>
<p>ReconToolKit is a comprehensive Open-Source Intelligence (OSINT) and network reconnaissance platform designed for cybersecurity professionals, ethical hackers, and security researchers.</p>

<h4>Key Features:</h4>
<ul>
<li><strong>Modular Architecture:</strong> Easy to extend with new reconnaissance modules</li>
<li><strong>Passive OSINT:</strong> Domain enumeration, WHOIS lookup, DNS analysis</li>
<li><strong>Active Reconnaissance:</strong> Port scanning, directory enumeration</li>
<li><strong>Modern GUI:</strong> Intuitive PyQt5-based interface</li>
<li><strong>Export Capabilities:</strong> JSON, HTML, and CSV report generation</li>
<li><strong>Secure Storage:</strong> Encrypted API key management</li>
</ul>

<h4>Ethical Use Only</h4>
<p><strong>IMPORTANT:</strong> This tool is intended for ethical hacking, educational purposes, and legitimate security assessments only. Always ensure you have explicit permission before scanning any targets.</p>
        """
        
        description_text.setHtml(description_content)
        layout.addWidget(description_text)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        close_button.setDefault(True)
        layout.addWidget(close_button)
