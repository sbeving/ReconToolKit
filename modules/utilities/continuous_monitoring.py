"""
Continuous Monitoring and Alerting Module
Advanced continuous monitoring and alerting system for ongoing reconnaissance.
"""

import asyncio
import logging
import json
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import hashlib
import pickle
from pathlib import Path
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import schedule
import threading
from dataclasses import dataclass, asdict
import sqlite3

from modules.base_module import BaseModule


@dataclass
class MonitoringRule:
    """Monitoring rule configuration."""
    id: str
    name: str
    module_name: str
    config: Dict[str, Any]
    frequency: int  # minutes
    threshold_type: str  # 'change', 'value', 'count'
    threshold_value: Any
    enabled: bool
    last_run: Optional[datetime] = None
    last_result_hash: Optional[str] = None
    alert_channels: List[str] = None


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    rule_id: str
    timestamp: datetime
    severity: str  # 'low', 'medium', 'high', 'critical'
    title: str
    description: str
    data: Dict[str, Any]
    acknowledged: bool = False


class ContinuousMonitoringModule(BaseModule):
    """Advanced continuous monitoring and alerting module."""
    
    def __init__(self):
        """Initialize the continuous monitoring module."""
        super().__init__(
        name = "Continuous Monitoring & Alerting",
        description = "Advanced continuous monitoring and alerting system",
        category = "utilities"
        )
        self.name = "Continuous Monitoring & Alerting"
        self.description = "Advanced continuous monitoring and alerting system"
        self.category = "utilities"
        self.author = "ReconToolKit Team"
        self.version = "1.0.0"
        
        # Initialize monitoring state
        self.monitoring_rules = []
        self.active_monitors = {}
        self.alert_history = []
        self.db_path = Path("data/monitoring.db")
        self.is_monitoring = False
        self.monitoring_thread = None
        
        # Alert channels
        self.alert_channels = {
            'email': self._send_email_alert,
            'webhook': self._send_webhook_alert,
            'file': self._write_file_alert,
            'database': self._store_database_alert
        }
        
        # Initialize database
        self._init_database()
        
        # Load existing rules
        self._load_monitoring_rules()
    
    def get_config_fields(self) -> List[Dict[str, Any]]:
        """Get configuration fields for the module."""
        return [
            {
                'name': 'monitoring_mode',
                'label': 'Monitoring Mode',
                'type': 'select',
                'options': ['setup', 'start', 'stop', 'status'],
                'default': 'setup',
                'help': 'Select monitoring operation mode'
            },
            {
                'name': 'rule_name',
                'label': 'Rule Name',
                'type': 'text',
                'required': False,
                'placeholder': 'Domain Change Monitor',
                'help': 'Name for the monitoring rule (setup mode only)'
            },
            {
                'name': 'monitored_module',
                'label': 'Module to Monitor',
                'type': 'select',
                'options': [
                    'domain_enumeration', 'port_scanner', 'web_crawler',
                    'vulnerability_scanner', 'ssl_analyzer', 'social_engineering'
                ],
                'default': 'domain_enumeration',
                'help': 'Module to monitor continuously'
            },
            {
                'name': 'target',
                'label': 'Monitoring Target',
                'type': 'text',
                'required': False,
                'placeholder': 'example.com',
                'help': 'Target for monitoring (domain, IP, URL)'
            },
            {
                'name': 'frequency',
                'label': 'Check Frequency (minutes)',
                'type': 'number',
                'default': 60,
                'min': 5,
                'max': 10080,  # 1 week
                'help': 'How often to check for changes'
            },
            {
                'name': 'threshold_type',
                'label': 'Alert Threshold Type',
                'type': 'select',
                'options': ['change_detected', 'value_threshold', 'count_threshold'],
                'default': 'change_detected',
                'help': 'Type of threshold for triggering alerts'
            },
            {
                'name': 'threshold_value',
                'label': 'Threshold Value',
                'type': 'text',
                'required': False,
                'placeholder': '10',
                'help': 'Threshold value (for value/count thresholds)'
            },
            {
                'name': 'alert_channels',
                'label': 'Alert Channels',
                'type': 'multiselect',
                'options': ['email', 'webhook', 'file', 'database'],
                'default': ['database', 'file'],
                'help': 'How to deliver alerts'
            },
            {
                'name': 'email_config',
                'label': 'Email Configuration',
                'type': 'textarea',
                'required': False,
                'placeholder': 'smtp_server:smtp.gmail.com\nsmtp_port:587\nusername:user@gmail.com\npassword:pass\nto:admin@company.com',
                'help': 'Email settings (key:value format)'
            },
            {
                'name': 'dashboard_enabled',
                'label': 'Enable Monitoring Dashboard',
                'type': 'checkbox',
                'default': True,
                'help': 'Enable web dashboard for monitoring status'
            }
        ]
    
    async def run(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run continuous monitoring operations.
        
        Args:
            config: Module configuration
            
        Returns:
            Dictionary containing monitoring results
        """
        try:
            mode = config.get('monitoring_mode', 'setup')
            self.logger.info(f"Running continuous monitoring in {mode} mode")
            
            if mode == 'setup':
                return await self._setup_monitoring_rule(config)
            elif mode == 'start':
                return await self._start_monitoring()
            elif mode == 'stop':
                return await self._stop_monitoring()
            elif mode == 'status':
                return await self._get_monitoring_status()
            else:
                return {
                    'error': f'Unknown monitoring mode: {mode}',
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            error_msg = f"Error in continuous monitoring: {str(e)}"
            self.logger.error(error_msg)
            return {
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
    
    async def _setup_monitoring_rule(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Setup a new monitoring rule."""
        try:
            # Create monitoring rule
            rule = MonitoringRule(
                id=hashlib.md5(f"{config.get('rule_name', 'rule')}_{time.time()}".encode()).hexdigest()[:8],
                name=config.get('rule_name', f'Monitor {config.get("target", "unknown")}'),
                module_name=config.get('monitored_module', 'domain_enumeration'),
                config={
                    'target': config.get('target'),
                    'module_config': self._get_module_config(config.get('monitored_module'), config)
                },
                frequency=config.get('frequency', 60),
                threshold_type=config.get('threshold_type', 'change_detected'),
                threshold_value=config.get('threshold_value'),
                enabled=True,
                alert_channels=config.get('alert_channels', ['database', 'file'])
            )
            
            # Save rule
            self._save_monitoring_rule(rule)
            self.monitoring_rules.append(rule)
            
            # Configure alert channels
            await self._configure_alert_channels(config)
            
            return {
                'status': 'success',
                'message': f'Monitoring rule "{rule.name}" created successfully',
                'rule_id': rule.id,
                'rule_details': asdict(rule),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Failed to setup monitoring rule: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    async def _start_monitoring(self) -> Dict[str, Any]:
        """Start continuous monitoring."""
        if self.is_monitoring:
            return {
                'status': 'info',
                'message': 'Monitoring is already running',
                'active_rules': len(self.monitoring_rules),
                'timestamp': datetime.now().isoformat()
            }
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        return {
            'status': 'success',
            'message': 'Continuous monitoring started',
            'active_rules': len([r for r in self.monitoring_rules if r.enabled]),
            'monitoring_rules': [{'id': r.id, 'name': r.name, 'frequency': r.frequency} 
                               for r in self.monitoring_rules if r.enabled],
            'timestamp': datetime.now().isoformat()
        }
    
    async def _stop_monitoring(self) -> Dict[str, Any]:
        """Stop continuous monitoring."""
        self.is_monitoring = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        return {
            'status': 'success',
            'message': 'Continuous monitoring stopped',
            'timestamp': datetime.now().isoformat()
        }
    
    async def _get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        status = {
            'monitoring_active': self.is_monitoring,
            'total_rules': len(self.monitoring_rules),
            'enabled_rules': len([r for r in self.monitoring_rules if r.enabled]),
            'recent_alerts': self._get_recent_alerts(24),  # Last 24 hours
            'rule_status': [],
            'system_health': await self._check_system_health(),
            'timestamp': datetime.now().isoformat()
        }
        
        for rule in self.monitoring_rules:
            rule_status = {
                'id': rule.id,
                'name': rule.name,
                'enabled': rule.enabled,
                'last_run': rule.last_run.isoformat() if rule.last_run else None,
                'next_run': self._calculate_next_run(rule).isoformat() if rule.enabled else None,
                'frequency': rule.frequency,
                'module': rule.module_name
            }
            status['rule_status'].append(rule_status)
        
        return status
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        self.logger.info("Starting monitoring loop")
        
        while self.is_monitoring:
            try:
                current_time = datetime.now()
                
                for rule in self.monitoring_rules:
                    if not rule.enabled:
                        continue
                    
                    # Check if it's time to run this rule
                    if self._should_run_rule(rule, current_time):
                        self.logger.info(f"Running monitoring rule: {rule.name}")
                        
                        try:
                            # Run the monitoring check
                            asyncio.run(self._execute_monitoring_rule(rule))
                            rule.last_run = current_time
                            self._update_rule_in_db(rule)
                            
                        except Exception as e:
                            self.logger.error(f"Error executing rule {rule.name}: {e}")
                            
                            # Create error alert
                            alert = Alert(
                                id=hashlib.md5(f"error_{rule.id}_{time.time()}".encode()).hexdigest()[:8],
                                rule_id=rule.id,
                                timestamp=current_time,
                                severity='high',
                                title=f'Monitoring Rule Error: {rule.name}',
                                description=f'Failed to execute monitoring rule: {str(e)}',
                                data={'error': str(e), 'rule': rule.name}
                            )
                            
                            asyncio.run(self._process_alert(alert, rule.alert_channels))
                
                # Sleep for 1 minute before next check
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Continue monitoring despite errors
        
        self.logger.info("Monitoring loop stopped")
    
    async def _execute_monitoring_rule(self, rule: MonitoringRule):
        """Execute a monitoring rule."""
        try:
            # Import and run the appropriate module
            module_class = await self._get_module_class(rule.module_name)
            module_instance = module_class()
            
            # Run the module with the rule's configuration
            result = await module_instance.run(rule.config['module_config'])
            
            # Calculate result hash for change detection
            result_hash = hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
            
            # Check if alert should be triggered
            should_alert, alert_details = self._evaluate_threshold(rule, result, result_hash)
            
            if should_alert:
                alert = Alert(
                    id=hashlib.md5(f"{rule.id}_{time.time()}".encode()).hexdigest()[:8],
                    rule_id=rule.id,
                    timestamp=datetime.now(),
                    severity=alert_details.get('severity', 'medium'),
                    title=f'Alert: {rule.name}',
                    description=alert_details.get('description', 'Monitoring threshold exceeded'),
                    data={
                        'rule_name': rule.name,
                        'threshold_type': rule.threshold_type,
                        'current_result': result,
                        'previous_hash': rule.last_result_hash,
                        'current_hash': result_hash
                    }
                )
                
                await self._process_alert(alert, rule.alert_channels)
            
            # Update rule with new result hash
            rule.last_result_hash = result_hash
            
        except Exception as e:
            self.logger.error(f"Error executing monitoring rule {rule.name}: {e}")
            raise
    
    def _evaluate_threshold(self, rule: MonitoringRule, result: Dict[str, Any], result_hash: str) -> tuple[bool, Dict[str, Any]]:
        """Evaluate if alert threshold is met."""
        if rule.threshold_type == 'change_detected':
            if rule.last_result_hash and rule.last_result_hash != result_hash:
                return True, {
                    'severity': 'medium',
                    'description': f'Change detected in {rule.name} monitoring results'
                }
        
        elif rule.threshold_type == 'value_threshold':
            # Extract numeric value from result
            value = self._extract_numeric_value(result)
            threshold = float(rule.threshold_value) if rule.threshold_value else 0
            
            if value > threshold:
                return True, {
                    'severity': 'high',
                    'description': f'Value threshold exceeded: {value} > {threshold}'
                }
        
        elif rule.threshold_type == 'count_threshold':
            # Count items in result
            count = self._count_items_in_result(result)
            threshold = int(rule.threshold_value) if rule.threshold_value else 0
            
            if count > threshold:
                return True, {
                    'severity': 'medium',
                    'description': f'Count threshold exceeded: {count} > {threshold}'
                }
        
        return False, {}
    
    async def _process_alert(self, alert: Alert, channels: List[str]):
        """Process and send alert through configured channels."""
        self.alert_history.append(alert)
        self._store_alert_in_db(alert)
        
        for channel in channels:
            if channel in self.alert_channels:
                try:
                    await self.alert_channels[channel](alert)
                    self.logger.info(f"Alert sent via {channel}: {alert.title}")
                except Exception as e:
                    self.logger.error(f"Failed to send alert via {channel}: {e}")
    
    async def _send_email_alert(self, alert: Alert):
        """Send alert via email."""
        # This would be configured during setup
        email_config = getattr(self, 'email_config', {})
        
        if not email_config:
            self.logger.warning("Email configuration not found")
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = email_config['username']
            msg['To'] = email_config['to']
            msg['Subject'] = f"[{alert.severity.upper()}] {alert.title}"
            
            body = f"""
            Alert Details:
            - Severity: {alert.severity}
            - Timestamp: {alert.timestamp}
            - Description: {alert.description}
            - Rule ID: {alert.rule_id}
            
            Additional Data:
            {json.dumps(alert.data, indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            context = ssl.create_default_context()
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls(context=context)
                server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
                
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    async def _send_webhook_alert(self, alert: Alert):
        """Send alert via webhook."""
        # Placeholder for webhook implementation
        self.logger.info(f"Webhook alert: {alert.title}")
    
    async def _write_file_alert(self, alert: Alert):
        """Write alert to file."""
        try:
            alerts_dir = Path("logs/alerts")
            alerts_dir.mkdir(exist_ok=True)
            
            alert_file = alerts_dir / f"alerts_{datetime.now().strftime('%Y-%m-%d')}.json"
            
            alert_data = {
                'id': alert.id,
                'rule_id': alert.rule_id,
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity,
                'title': alert.title,
                'description': alert.description,
                'data': alert.data
            }
            
            # Append to daily alert file
            alerts = []
            if alert_file.exists():
                with open(alert_file, 'r') as f:
                    alerts = json.load(f)
            
            alerts.append(alert_data)
            
            with open(alert_file, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Failed to write file alert: {e}")
    
    async def _store_database_alert(self, alert: Alert):
        """Store alert in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (id, rule_id, timestamp, severity, title, description, data, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id, alert.rule_id, alert.timestamp.isoformat(),
                alert.severity, alert.title, alert.description,
                json.dumps(alert.data), alert.acknowledged
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store alert in database: {e}")
    
    def _init_database(self):
        """Initialize monitoring database."""
        try:
            self.db_path.parent.mkdir(exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create monitoring rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    config TEXT NOT NULL,
                    frequency INTEGER NOT NULL,
                    threshold_type TEXT NOT NULL,
                    threshold_value TEXT,
                    enabled BOOLEAN NOT NULL,
                    last_run TIMESTAMP,
                    last_result_hash TEXT,
                    alert_channels TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    data TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rule_id) REFERENCES monitoring_rules (id)
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def _save_monitoring_rule(self, rule: MonitoringRule):
        """Save monitoring rule to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO monitoring_rules 
                (id, name, module_name, config, frequency, threshold_type, threshold_value, 
                 enabled, last_run, last_result_hash, alert_channels)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.id, rule.name, rule.module_name, json.dumps(rule.config),
                rule.frequency, rule.threshold_type, rule.threshold_value,
                rule.enabled, rule.last_run, rule.last_result_hash,
                json.dumps(rule.alert_channels)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to save monitoring rule: {e}")
    
    def _load_monitoring_rules(self):
        """Load monitoring rules from database."""
        try:
            if not self.db_path.exists():
                return
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM monitoring_rules WHERE enabled = TRUE")
            rows = cursor.fetchall()
            
            for row in rows:
                rule = MonitoringRule(
                    id=row[0],
                    name=row[1],
                    module_name=row[2],
                    config=json.loads(row[3]),
                    frequency=row[4],
                    threshold_type=row[5],
                    threshold_value=row[6],
                    enabled=bool(row[7]),
                    last_run=datetime.fromisoformat(row[8]) if row[8] else None,
                    last_result_hash=row[9],
                    alert_channels=json.loads(row[10]) if row[10] else []
                )
                self.monitoring_rules.append(rule)
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to load monitoring rules: {e}")
    
    def _update_rule_in_db(self, rule: MonitoringRule):
        """Update rule in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE monitoring_rules 
                SET last_run = ?, last_result_hash = ?
                WHERE id = ?
            """, (rule.last_run, rule.last_result_hash, rule.id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to update rule in database: {e}")
    
    def _store_alert_in_db(self, alert: Alert):
        """Store alert in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (id, rule_id, timestamp, severity, title, description, data, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id, alert.rule_id, alert.timestamp.isoformat(),
                alert.severity, alert.title, alert.description,
                json.dumps(alert.data), alert.acknowledged
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store alert: {e}")
    
    def _get_recent_alerts(self, hours: int) -> List[Dict[str, Any]]:
        """Get recent alerts from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since = datetime.now() - timedelta(hours=hours)
            cursor.execute("""
                SELECT id, rule_id, timestamp, severity, title, description, acknowledged
                FROM alerts 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 50
            """, (since.isoformat(),))
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'id': row[0],
                    'rule_id': row[1],
                    'timestamp': row[2],
                    'severity': row[3],
                    'title': row[4],
                    'description': row[5],
                    'acknowledged': bool(row[6])
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get recent alerts: {e}")
            return []
    
    async def _configure_alert_channels(self, config: Dict[str, Any]):
        """Configure alert channels."""
        email_config_str = config.get('email_config', '')
        if email_config_str:
            email_config = {}
            for line in email_config_str.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    email_config[key.strip()] = value.strip()
            
            self.email_config = email_config
    
    def _get_module_config(self, module_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Get module-specific configuration."""
        base_config = {'target': config.get('target')}
        
        # Add module-specific configurations
        module_configs = {
            'domain_enumeration': {
                'target_domain': config.get('target'),
                'include_subdomains': True,
                'dns_enumeration': True
            },
            'port_scanner': {
                'target': config.get('target'),
                'port_range': '1-1000',
                'scan_type': 'tcp'
            },
            'vulnerability_scanner': {
                'target': config.get('target'),
                'scan_depth': 'basic'
            }
        }
        
        return module_configs.get(module_name, base_config)
    
    async def _get_module_class(self, module_name: str):
        """Get module class by name."""
        # This would dynamically import the appropriate module
        # For now, return a placeholder
        from modules.passive.domain_enumeration import DomainEnumerationModule
        
        module_classes = {
            'domain_enumeration': DomainEnumerationModule,
            # Add other modules as needed
        }
        
        return module_classes.get(module_name, DomainEnumerationModule)
    
    def _should_run_rule(self, rule: MonitoringRule, current_time: datetime) -> bool:
        """Check if rule should be run now."""
        if not rule.last_run:
            return True
        
        time_since_last_run = current_time - rule.last_run
        return time_since_last_run.total_seconds() >= (rule.frequency * 60)
    
    def _calculate_next_run(self, rule: MonitoringRule) -> datetime:
        """Calculate next run time for rule."""
        if not rule.last_run:
            return datetime.now()
        
        return rule.last_run + timedelta(minutes=rule.frequency)
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check system health."""
        return {
            'status': 'healthy',
            'monitoring_thread_alive': self.monitoring_thread.is_alive() if self.monitoring_thread else False,
            'database_accessible': self.db_path.exists(),
            'memory_usage': 'unknown',  # Could integrate psutil
            'last_health_check': datetime.now().isoformat()
        }
    
    def _extract_numeric_value(self, result: Dict[str, Any]) -> float:
        """Extract numeric value from result for threshold comparison."""
        # Try to find numeric values in the result
        if isinstance(result, dict):
            for key, value in result.items():
                if isinstance(value, (int, float)):
                    return float(value)
                elif isinstance(value, list):
                    return float(len(value))
        
        return 0.0
    
    def _count_items_in_result(self, result: Dict[str, Any]) -> int:
        """Count items in result."""
        if isinstance(result, dict):
            # Count total items in all lists
            count = 0
            for value in result.values():
                if isinstance(value, list):
                    count += len(value)
                elif isinstance(value, dict):
                    count += len(value)
            return count
        
        return 0
    
    def cleanup(self):
        """Clean up module resources."""
        if self.is_monitoring:
            self.is_monitoring = False
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5)


# Create module instance
module = ContinuousMonitoringModule()
