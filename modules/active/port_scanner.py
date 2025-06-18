"""
Port Scanner Module
Performs comprehensive port scanning using python-nmap.
"""

import logging
import nmap
import socket
import time
from typing import Dict, Any, List, Optional
from modules.base_module import BaseModule


class PortScannerModule(BaseModule):
    """Port scanning module for network reconnaissance."""
    
    def __init__(self):
        super().__init__(
            name="Port Scanner",
            description="Network port scanning with service detection and OS fingerprinting",
            category="active"
        )
        
        self.scanner = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """
        Get list of input fields required for this module.
        
        Returns:
            List[Dict[str, Any]]: List of input field definitions
        """
        return [
            {
                'name': 'target',
                'type': 'text',
                'label': 'Target Host/IP/Range',
                'required': True,
                'default': '',
                'placeholder': 'e.g., example.com, 192.168.1.1, 10.0.0.1-10'
            },
            {
                'name': 'ports',
                'type': 'text',
                'label': 'Port Range',
                'required': False,
                'default': '1-1000',
                'placeholder': 'e.g., 21-25,80,443,8080-8090'
            },
            {
                'name': 'scan_type',
                'type': 'select',
                'label': 'Scan Type',
                'required': True,
                'default': 'SYN',
                'options': [
                    ('SYN Scan (Recommended)', 'SYN'),
                    ('Connect Scan', 'CONNECT'),
                    ('UDP Scan', 'UDP'),
                    ('Comprehensive', 'ALL')
                ]
            },
            {
                'name': 'service_detection',
                'type': 'checkbox',
                'label': 'Service Version Detection',
                'required': False,
                'default': True
            },
            {
                'name': 'os_detection',
                'type': 'checkbox',
                'label': 'OS Detection',
                'required': False,
                'default': False
            },
            {
                'name': 'timing',
                'type': 'select',
                'label': 'Scan Timing',
                'required': True,
                'default': '3',
                'options': [
                    ('Paranoid (0)', '0'),
                    ('Sneaky (1)', '1'),
                    ('Polite (2)', '2'),
                    ('Normal (3)', '3'),
                    ('Aggressive (4)', '4'),
                    ('Insane (5)', '5')
                ]
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        """
        Validate input parameters.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            
        Returns:
            Optional[str]: Error message if validation fails, None if valid
        """
        if not inputs.get('target'):
            return "Target host/IP is required"
        
        ports = inputs.get('ports', '1-1000')
        if ports:
            # Basic port format validation
            try:
                for part in ports.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if start < 1 or end > 65535 or start > end:
                            return "Invalid port range: ports must be between 1-65535"
                    else:
                        port = int(part)
                        if port < 1 or port > 65535:
                            return "Invalid port: ports must be between 1-65535"
            except ValueError:
                return "Invalid port format. Use comma-separated values or ranges (e.g., 80,443,8000-8100)"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run port scanning.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            config (Dict[str, Any]): Configuration parameters
            
        Returns:
            Dict[str, Any]: Scan results
        """
        target = inputs.get('target', '')
        ports = inputs.get('ports', '1-1000')
        scan_type = inputs.get('scan_type', 'SYN')
        service_detection = inputs.get('service_detection', True)
        os_detection = inputs.get('os_detection', False)
        timing = inputs.get('timing', '3')
        
        self.logger.info(f"Starting port scan on {target} (ports: {ports})")
        self.update_progress(f"Initializing port scan on {target}...", 5)
        
        # Build nmap arguments
        args = f"-T{timing} "
        
        if scan_type == 'SYN':
            args += "-sS "
        elif scan_type == 'CONNECT':
            args += "-sT "
        elif scan_type == 'UDP':
            args += "-sU "
        elif scan_type == 'ALL':
            args += "-sS -sU -sV -sC "
        
        if service_detection:
            args += "-sV "
        
        if os_detection:
            args += "-O "
        
        try:
            self.update_progress(f"Scanning {target} with nmap...", 10)
            self.logger.debug(f"Running nmap with args: {args} on {target} ports {ports}")
            
            # Run the scan - this may take time for large scans
            start_time = time.time()
            self.scanner.scan(hosts=target, ports=ports, arguments=args)
            scan_time = time.time() - start_time
            
            self.update_progress(f"Processing scan results...", 80)
            
            # Process results
            results = {
                'scan_info': {
                    'target': target,
                    'scan_type': scan_type,
                    'ports_scanned': ports,
                    'scan_time': f"{scan_time:.2f} seconds",
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'nmap_version': self.scanner.nmap_version()
                },
                'hosts': []
            }
            
            # Process each host
            for host in self.scanner.all_hosts():
                host_info = {
                    'host': host,
                    'status': self.scanner[host].state(),
                    'open_ports': [],
                    'hostname': []
                }
                
                # Get hostname information
                if 'hostnames' in self.scanner[host]:
                    for hostname in self.scanner[host]['hostnames']:
                        if isinstance(hostname, dict) and 'name' in hostname:
                            host_info['hostname'].append(hostname['name'])
                        elif isinstance(hostname, str):
                            host_info['hostname'].append(hostname)
                
                # OS detection results
                if os_detection and 'osmatch' in self.scanner[host]:
                    host_info['os_matches'] = []
                    for osmatch in self.scanner[host]['osmatch']:
                        if isinstance(osmatch, dict) and 'name' in osmatch:
                            host_info['os_matches'].append({
                                'name': osmatch['name'],
                                'accuracy': osmatch.get('accuracy', 'unknown')
                            })
                
                # Process each protocol (usually tcp, udp, etc.)
                for proto in self.scanner[host].all_protocols():
                    for port in sorted(self.scanner[host][proto].keys()):
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': self.scanner[host][proto][port]['state'],
                            'service': {
                                'name': self.scanner[host][proto][port].get('name', 'unknown'),
                                'product': self.scanner[host][proto][port].get('product', ''),
                                'version': self.scanner[host][proto][port].get('version', ''),
                                'extrainfo': self.scanner[host][proto][port].get('extrainfo', '')
                            }
                        }
                        host_info['open_ports'].append(port_info)
                
                results['hosts'].append(host_info)
            
            # Generate summary
            total_hosts = len(self.scanner.all_hosts())
            total_open_ports = sum(len(host['open_ports']) for host in results['hosts'])
            
            self.update_progress(f"Scan completed: Found {total_open_ports} open ports on {total_hosts} hosts", 100)
            
            # Add summary section
            results['summary'] = {
                'total_hosts': total_hosts,
                'total_open_ports': total_open_ports,
                'scan_duration': f"{scan_time:.2f} seconds"
            }
            
            return results
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {e}")
            raise Exception(f"Nmap scan error: {e}")
        except Exception as e:
            self.logger.error(f"Port scanning error: {e}")
            raise Exception(f"Port scanning error: {str(e)}")
