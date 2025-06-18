#!/usr/bin/env python3
"""
ReconToolKit Installation Test
Tests if all dependencies are properly installed and the application can start.
"""

import sys
import os

def test_imports():
    """Test if all required packages can be imported."""
    print("Testing Python package imports...")
    
    try:
        import PyQt5
        print("✓ PyQt5 imported successfully")
    except ImportError as e:
        print(f"✗ PyQt5 import failed: {e}")
        return False
    
    try:
        import requests
        print("✓ requests imported successfully")
    except ImportError as e:
        print(f"✗ requests import failed: {e}")
        return False
    
    try:
        import dns.resolver
        print("✓ dnspython imported successfully")
    except ImportError as e:
        print(f"✗ dnspython import failed: {e}")
        return False
    
    try:
        import whois
        print("✓ python-whois imported successfully")
    except ImportError as e:
        print(f"✗ python-whois import failed: {e}")
        return False
    
    try:
        import bs4
        print("✓ beautifulsoup4 imported successfully")
    except ImportError as e:
        print(f"✗ beautifulsoup4 import failed: {e}")
        return False
    
    try:
        from Crypto.Cipher import AES
        print("✓ pycryptodome imported successfully")
    except ImportError as e:
        print(f"✗ pycryptodome import failed: {e}")
        return False
    
    try:
        import reportlab
        print("✓ reportlab imported successfully")
    except ImportError as e:
        print(f"✗ reportlab import failed: {e}")
        return False
    
    try:
        import jinja2
        print("✓ jinja2 imported successfully")
    except ImportError as e:
        print(f"✗ jinja2 import failed: {e}")
        return False
    
    # Test new module dependencies
    try:
        import nmap
        print("✓ python-nmap imported successfully")
    except ImportError as e:
        print(f"✗ python-nmap import failed: {e}")
        return False
    
    try:
        import aiohttp
        print("✓ aiohttp imported successfully")
    except ImportError as e:
        print(f"✗ aiohttp import failed: {e}")
        return False
        
    try:
        import asyncio
        print("✓ asyncio imported successfully")
    except ImportError as e:
        print(f"✗ asyncio import failed: {e}")
        return False
        
    try:
        import aiodns
        print("✓ aiodns imported successfully")
    except ImportError as e:
        print(f"✗ aiodns import failed: {e}")
        return False
  
    
    return True

def test_python_version():
    """Test if Python version is compatible."""
    print(f"Testing Python version...")
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("✗ Python 3.7 or higher is required")
        return False
    
    print("✓ Python version is compatible")
    return True

def test_core_modules():
    """Test if core ReconToolKit modules can be imported."""
    print("Testing ReconToolKit core modules...")
    
    # Add project root to path
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)
    
    try:
        from core.database import DatabaseManager
        print("✓ DatabaseManager imported successfully")
    except ImportError as e:
        print(f"✗ DatabaseManager import failed: {e}")
        return False
    
    try:
        from core.config import ConfigManager
        print("✓ ConfigManager imported successfully")
    except ImportError as e:
        print(f"✗ ConfigManager import failed: {e}")
        return False
    
    try:
        from modules.base_module import BaseModule
        print("✓ BaseModule imported successfully")
    except ImportError as e:
        print(f"✗ BaseModule import failed: {e}")
        return False
    
    # Test new active modules
    try:
        from modules.active.port_scanner import PortScannerModule
        print("✓ PortScannerModule imported successfully")
    except ImportError as e:
        print(f"✗ PortScannerModule import failed: {e}")
        return False
        
    try:
        from modules.active.web_directory_enum import WebDirectoryEnumerationModule
        print("✓ WebDirectoryEnumerationModule imported successfully")
    except ImportError as e:
        print(f"✗ WebDirectoryEnumerationModule import failed: {e}")
        return False
        
    try:
        from modules.active.web_fuzzer import WebFuzzerModule
        print("✓ WebFuzzerModule imported successfully")
    except ImportError as e:
        print(f"✗ WebFuzzerModule import failed: {e}")
        return False
    
    return True

def test_database_creation():
    """Test if database can be created."""
    print("Testing database creation...")
    
    try:
        # Add project root to path
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        from core.database import DatabaseManager
        
        # Create test database
        test_db_path = os.path.join(project_root, 'test_recontoolkit.db')
        db_manager = DatabaseManager(test_db_path)
        
        # Try to create a test project
        project_id = db_manager.create_project("Test Project", "Test Description")
        print(f"✓ Database created and test project created with ID: {project_id}")
        
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
        
        return True
        
    except Exception as e:
        print(f"✗ Database creation failed: {e}")
        return False

def main():
    """Main test function."""
    print("=" * 50)
    print("ReconToolKit Installation Test")
    print("=" * 50)
    print()
    
    all_tests_passed = True
    
    # Test Python version
    if not test_python_version():
        all_tests_passed = False
    print()
    
    # Test package imports
    if not test_imports():
        all_tests_passed = False
    print()
    
    # Test core modules
    if not test_core_modules():
        all_tests_passed = False
    print()
    
    # Test database creation
    if not test_database_creation():
        all_tests_passed = False
    print()
    
    # Final result
    print("=" * 50)
    if all_tests_passed:
        print("✓ ALL TESTS PASSED!")
        print("ReconToolKit is ready to use.")
        print("Run 'python main.py' to start the application.")
    else:
        print("✗ SOME TESTS FAILED!")
        print("Please check the errors above and install missing dependencies.")
        print("Run 'pip install -r requirements.txt' to install required packages.")
    print("=" * 50)
    
    return 0 if all_tests_passed else 1

if __name__ == "__main__":
    sys.exit(main())
