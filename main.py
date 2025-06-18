#!/usr/bin/env python3
"""
ReconToolKit: A Comprehensive OSINT & Reconnaissance Platform
Main Entry Point

Author: ReconToolKit Development Team
Version: 1.0.0
License: MIT

DISCLAIMER: This tool is for ethical hacking, educational purposes, and legitimate 
security assessments only. Use with explicit permission from the target.
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from core.database import DatabaseManager
from core.config import ConfigManager
from gui.main_window import MainWindow


def setup_logging():
    """Configure logging for the application."""
    log_dir = os.path.join(project_root, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'recontoolkit.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("ReconToolKit starting up...")
    return logger


def main():
    """Main application entry point."""
    logger = setup_logging()
    
    try:
        # Create QApplication
        app = QApplication(sys.argv)
        app.setApplicationName("ReconToolKit")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("ReconToolKit Team")
        
        # Enable high DPI scaling
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        # Initialize core components
        logger.info("Initializing database...")
        db_manager = DatabaseManager()
        
        logger.info("Initializing configuration...")
        config_manager = ConfigManager()
        
        # Create and show main window
        logger.info("Creating main window...")
        main_window = MainWindow(db_manager, config_manager)
        main_window.show()
        
        logger.info("ReconToolKit GUI launched successfully")
        
        # Start the application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        logger.error(f"Failed to start ReconToolKit: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        # Ensure the required packages are installed
        import PyQt5
    except ImportError:
        print("PyQt5 is not installed. Please install it using 'pip install PyQt5'.")
        sys.exit(1)
    main()
    

