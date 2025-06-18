"""
ReconToolKit Database Manager
Handles SQLite database operations for storing scan results, configurations, and API keys.
"""

import sqlite3
import os
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib


class DatabaseManager:
    """Manages SQLite database operations for ReconToolKit."""
    
    def __init__(self, db_path: str = None):
        """
        Initialize the database manager.
        
        Args:
            db_path (str): Path to the SQLite database file
        """
        self.logger = logging.getLogger(__name__)
        
        if db_path is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, 'data', 'recontoolkit.db')
        
        self.db_path = db_path
        self._ensure_db_directory()
        self._initialize_database()
        self._encryption_key = self._get_or_create_encryption_key()
    
    def _ensure_db_directory(self):
        """Ensure the database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        os.makedirs(db_dir, exist_ok=True)
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for API keys."""
        key_file = os.path.join(os.path.dirname(self.db_path), '.key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = get_random_bytes(32)  # 256-bit key
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _initialize_database(self):
        """Initialize the database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Projects table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER,
                        module_name TEXT NOT NULL,
                        target TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        results TEXT,  -- JSON data
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects (id)
                    )
                ''')
                
                # Configuration table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS configurations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL UNIQUE,
                        value TEXT,
                        encrypted INTEGER DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Wordlists table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wordlists (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        file_path TEXT NOT NULL,
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Results summary table for quick access
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS results_summary (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        data_type TEXT,  -- 'domain', 'subdomain', 'email', 'port', etc.
                        value TEXT,
                        metadata TEXT,  -- Additional JSON metadata
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (id)
                    )
                ''')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {e}")
            raise
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data like API keys."""
        try:
            cipher = AES.new(self._encryption_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
            
            # Combine nonce, tag, and ciphertext
            encrypted_data = cipher.nonce + tag + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data like API keys."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract nonce, tag, and ciphertext
            nonce = encrypted_bytes[:16]
            tag = encrypted_bytes[16:32]
            ciphertext = encrypted_bytes[32:]
            
            cipher = AES.new(self._encryption_key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise
    
    def create_project(self, name: str, description: str = "") -> int:
        """Create a new project."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO projects (name, description) VALUES (?, ?)",
                    (name, description)
                )
                project_id = cursor.lastrowid
                conn.commit()
                self.logger.info(f"Created project: {name} (ID: {project_id})")
                return project_id
                
        except sqlite3.IntegrityError:
            raise ValueError(f"Project '{name}' already exists")
        except sqlite3.Error as e:
            self.logger.error(f"Error creating project: {e}")
            raise
    
    def get_projects(self) -> List[Dict[str, Any]]:
        """Get all projects."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching projects: {e}")
            return []
    
    def create_scan(self, project_id: int, module_name: str, target: str) -> int:
        """Create a new scan record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO scans (project_id, module_name, target) VALUES (?, ?, ?)",
                    (project_id, module_name, target)
                )
                scan_id = cursor.lastrowid
                conn.commit()
                self.logger.info(f"Created scan: {module_name} for {target} (ID: {scan_id})")
                return scan_id
                
        except sqlite3.Error as e:
            self.logger.error(f"Error creating scan: {e}")
            raise
    
    def update_scan_results(self, scan_id: int, results: Dict[str, Any], status: str = "completed"):
        """Update scan results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """UPDATE scans 
                       SET results = ?, status = ?, completed_at = CURRENT_TIMESTAMP 
                       WHERE id = ?""",
                    (json.dumps(results), status, scan_id)
                )
                conn.commit()
                self.logger.info(f"Updated scan results for scan ID: {scan_id}")
                
        except sqlite3.Error as e:
            self.logger.error(f"Error updating scan results: {e}")
            raise
    
    def get_scan_results(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get scan results by scan ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
                row = cursor.fetchone()
                
                if row:
                    result = dict(row)
                    if result['results']:
                        result['results'] = json.loads(result['results'])
                    return result
                return None
                
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching scan results: {e}")
            return None
    
    def set_config(self, key: str, value: str, encrypted: bool = False):
        """Set a configuration value."""
        try:
            if encrypted:
                value = self.encrypt_data(value)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT OR REPLACE INTO configurations (key, value, encrypted, updated_at) 
                       VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                    (key, value, 1 if encrypted else 0)
                )
                conn.commit()
                self.logger.info(f"Set configuration: {key}")
                
        except sqlite3.Error as e:
            self.logger.error(f"Error setting configuration: {e}")
            raise
    
    def get_config(self, key: str, default: str = None) -> Optional[str]:
        """Get a configuration value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT value, encrypted FROM configurations WHERE key = ?", (key,))
                row = cursor.fetchone()
                
                if row:
                    value = row['value']
                    if row['encrypted']:
                        value = self.decrypt_data(value)
                    return value
                return default
                
        except sqlite3.Error as e:
            self.logger.error(f"Error getting configuration: {e}")
            return default
    
    def get_all_configs(self) -> Dict[str, str]:
        """Get all configuration values (non-encrypted only for security)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT key, value FROM configurations WHERE encrypted = 0")
                return {row['key']: row['value'] for row in cursor.fetchall()}
                
        except sqlite3.Error as e:
            self.logger.error(f"Error getting configurations: {e}")
            return {}
    
    def add_wordlist(self, name: str, file_path: str, description: str = ""):
        """Add a wordlist to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO wordlists (name, file_path, description) VALUES (?, ?, ?)",
                    (name, file_path, description)
                )
                conn.commit()
                self.logger.info(f"Added wordlist: {name}")
                
        except sqlite3.IntegrityError:
            raise ValueError(f"Wordlist '{name}' already exists")
        except sqlite3.Error as e:
            self.logger.error(f"Error adding wordlist: {e}")
            raise
    
    def get_wordlists(self) -> List[Dict[str, Any]]:
        """Get all wordlists."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM wordlists ORDER BY name")
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching wordlists: {e}")
            return []
    
    def add_result_summary(self, scan_id: int, data_type: str, value: str, metadata: Dict[str, Any] = None):
        """Add a result summary entry for quick searching."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO results_summary (scan_id, data_type, value, metadata) VALUES (?, ?, ?, ?)",
                    (scan_id, data_type, value, json.dumps(metadata) if metadata else None)
                )
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error adding result summary: {e}")
    
    def search_results(self, query: str, data_type: str = None) -> List[Dict[str, Any]]:
        """Search through results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                sql = """
                    SELECT rs.*, s.module_name, s.target, s.started_at, p.name as project_name
                    FROM results_summary rs
                    JOIN scans s ON rs.scan_id = s.id
                    JOIN projects p ON s.project_id = p.id
                    WHERE rs.value LIKE ?
                """
                params = [f"%{query}%"]
                
                if data_type:
                    sql += " AND rs.data_type = ?"
                    params.append(data_type)
                
                sql += " ORDER BY rs.created_at DESC"
                
                cursor.execute(sql, params)
                results = [dict(row) for row in cursor.fetchall()]
                
                # Parse metadata JSON
                for result in results:
                    if result['metadata']:
                        result['metadata'] = json.loads(result['metadata'])
                
                return results
                
        except sqlite3.Error as e:
            self.logger.error(f"Error searching results: {e}")
            return []
