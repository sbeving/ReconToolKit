"""
SSL/TLS Analyzer Module
Comprehensive SSL/TLS certificate and configuration analysis.
"""

import logging
import ssl
import socket
import asyncio
import aiohttp
import OpenSSL
import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from modules.base_module import BaseModule


class SSLTLSAnalyzer(BaseModule):
    """Advanced SSL/TLS analysis module."""
    
    def __init__(self):
        super().__init__(
            name="SSL/TLS Analyzer",
            description="Comprehensive SSL/TLS certificate and security configuration analysis",
            category="active"
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Weak cipher suites
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'anon',
            'ADH', 'AECDH', 'EXP', 'LOW', 'MEDIUM'
        ]
        
        # Strong cipher suites
        self.strong_ciphers = [
            'AES256-GCM', 'AES128-GCM', 'CHACHA20-POLY1305', 'AES256-SHA256', 'AES128-SHA256'
        ]

    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'target_host',
                'type': 'text',
                'label': 'Target Host',
                'required': True,
                'default': '',
                'placeholder': 'example.com'
            },
            {
                'name': 'target_port',
                'type': 'number',
                'label': 'Target Port',
                'required': False,
                'default': 443,
                'min': 1,
                'max': 65535
            },
            {
                'name': 'check_certificate_chain',
                'type': 'checkbox',
                'label': 'Analyze Certificate Chain',
                'required': False,
                'default': True
            },
            {
                'name': 'check_cipher_suites',
                'type': 'checkbox',
                'label': 'Test Cipher Suites',
                'required': False,
                'default': True
            },
            {
                'name': 'check_protocols',
                'type': 'checkbox',
                'label': 'Test SSL/TLS Protocols',
                'required': False,
                'default': True
            },
            {
                'name': 'check_vulnerabilities',
                'type': 'checkbox',
                'label': 'Check for Known Vulnerabilities',
                'required': False,
                'default': True
            },
            {
                'name': 'timeout',
                'type': 'number',
                'label': 'Connection Timeout (seconds)',
                'required': False,
                'default': 10,
                'min': 5,
                'max': 60
            }
        ]

    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        target_host = inputs.get('target_host', '').strip()
        if not target_host:
            return "Target host is required"
        
        target_port = inputs.get('target_port', 443)
        if not isinstance(target_port, int) or target_port < 1 or target_port > 65535:
            return "Target port must be between 1 and 65535"
        
        return None

    def get_certificate_info(self, host: str, port: int, timeout: int) -> Dict[str, Any]:
        """Get SSL certificate information."""
        self.update_progress("Retrieving SSL certificate...", 20)
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    
                    # Parse certificate with OpenSSL for more details
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    # Extract certificate details
                    cert_details = {
                        'subject': dict(x[0] for x in cert_info['subject']),
                        'issuer': dict(x[0] for x in cert_info['issuer']),
                        'version': cert_info.get('version', 'Unknown'),
                        'serial_number': str(cert.get_serial_number()),
                        'not_before': cert_info.get('notBefore'),
                        'not_after': cert_info.get('notAfter'),
                        'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
                        'public_key_algorithm': cert.get_pubkey().type(),
                        'public_key_bits': cert.get_pubkey().bits(),
                        'extensions': []
                    }
                    
                    # Parse extensions
                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        cert_details['extensions'].append({
                            'name': ext.get_short_name().decode('utf-8'),
                            'critical': ext.get_critical(),
                            'value': str(ext)
                        })
                    
                    # Check certificate validity
                    now = datetime.datetime.now()
                    not_before = datetime.datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    cert_details['is_valid'] = not_before <= now <= not_after
                    cert_details['days_to_expiry'] = (not_after - now).days
                    cert_details['is_expired'] = now > not_after
                    cert_details['is_self_signed'] = cert_details['subject'] == cert_details['issuer']
                    
                    # Subject Alternative Names
                    san_ext = next((ext for ext in cert_details['extensions'] if ext['name'] == 'subjectAltName'), None)
                    if san_ext:
                        cert_details['subject_alt_names'] = [name.strip() for name in san_ext['value'].replace('DNS:', '').split(',')]
                    else:
                        cert_details['subject_alt_names'] = []
                    
                    return cert_details
                    
        except Exception as e:
            self.logger.error(f"Error getting certificate info: {e}")
            return {'error': str(e)}

    def test_cipher_suites(self, host: str, port: int, timeout: int) -> Dict[str, Any]:
        """Test supported cipher suites."""
        self.update_progress("Testing cipher suites...", 40)
        
        supported_ciphers = []
        weak_ciphers_found = []
        strong_ciphers_found = []
        
        # Common cipher suites to test
        test_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'ECDHE-RSA-RC4-SHA',
            'RC4-SHA',
            'RC4-MD5',
            'DES-CBC3-SHA',
            'DES-CBC-SHA',
            'EXP-RC4-MD5',
            'EXP-DES-CBC-SHA',
            'NULL-SHA',
            'NULL-MD5'
        ]
        
        for cipher in test_ciphers:
            if not self.should_continue():
                break
                
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            supported_ciphers.append({
                                'name': cipher_info[0],
                                'version': cipher_info[1],
                                'bits': cipher_info[2]
                            })
                            
                            # Check if weak or strong
                            if any(weak in cipher_info[0].upper() for weak in self.weak_ciphers):
                                weak_ciphers_found.append(cipher_info[0])
                            elif any(strong in cipher_info[0].upper() for strong in self.strong_ciphers):
                                strong_ciphers_found.append(cipher_info[0])
                                
            except Exception:
                continue
        
        return {
            'supported_ciphers': supported_ciphers,
            'weak_ciphers': weak_ciphers_found,
            'strong_ciphers': strong_ciphers_found,
            'total_supported': len(supported_ciphers)
        }

    def test_ssl_protocols(self, host: str, port: int, timeout: int) -> Dict[str, Any]:
        """Test supported SSL/TLS protocol versions."""
        self.update_progress("Testing SSL/TLS protocols...", 60)
        
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern systems
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Try TLSv1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
        
        supported_protocols = []
        deprecated_protocols = []
        
        for protocol_name, protocol_const in protocols.items():
            if not self.should_continue():
                break
                
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported_protocols.append(protocol_name)
                        
                        # Mark deprecated protocols
                        if protocol_name in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                            deprecated_protocols.append(protocol_name)
                            
            except Exception:
                continue
        
        return {
            'supported_protocols': supported_protocols,
            'deprecated_protocols': deprecated_protocols,
            'secure_protocols': [p for p in supported_protocols if p not in deprecated_protocols]
        }

    def check_ssl_vulnerabilities(self, host: str, port: int, cipher_info: Dict[str, Any], 
                                protocol_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for known SSL/TLS vulnerabilities."""
        self.update_progress("Checking for SSL/TLS vulnerabilities...", 80)
        
        vulnerabilities = []
        
        # Check for deprecated protocols
        if 'SSLv2' in protocol_info.get('supported_protocols', []):
            vulnerabilities.append({
                'name': 'SSLv2 Enabled',
                'severity': 'high',
                'description': 'SSLv2 is deprecated and insecure',
                'cve': 'CVE-2011-3389',
                'recommendation': 'Disable SSLv2 support'
            })
        
        if 'SSLv3' in protocol_info.get('supported_protocols', []):
            vulnerabilities.append({
                'name': 'SSLv3 Enabled (POODLE)',
                'severity': 'high',
                'description': 'SSLv3 is vulnerable to POODLE attack',
                'cve': 'CVE-2014-3566',
                'recommendation': 'Disable SSLv3 support'
            })
        
        if 'TLSv1.0' in protocol_info.get('supported_protocols', []):
            vulnerabilities.append({
                'name': 'TLSv1.0 Enabled',
                'severity': 'medium',
                'description': 'TLSv1.0 is deprecated and should be disabled',
                'cve': 'CVE-2014-3566',
                'recommendation': 'Disable TLSv1.0 support'
            })
        
        # Check for weak ciphers
        weak_ciphers = cipher_info.get('weak_ciphers', [])
        if weak_ciphers:
            vulnerabilities.append({
                'name': 'Weak Cipher Suites',
                'severity': 'medium',
                'description': f'Weak cipher suites detected: {", ".join(weak_ciphers)}',
                'cve': 'Various',
                'recommendation': 'Disable weak cipher suites and use only strong ciphers'
            })
        
        # Check for RC4
        if any('RC4' in cipher for cipher in cipher_info.get('supported_ciphers', [])):
            vulnerabilities.append({
                'name': 'RC4 Cipher Support',
                'severity': 'medium',
                'description': 'RC4 cipher is vulnerable to various attacks',
                'cve': 'CVE-2013-2566',
                'recommendation': 'Disable RC4 cipher support'
            })
        
        return vulnerabilities

    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run the SSL/TLS analysis."""
        target_host = inputs.get('target_host').strip()
        target_port = inputs.get('target_port', 443)
        check_cert_chain = inputs.get('check_certificate_chain', True)
        check_ciphers = inputs.get('check_cipher_suites', True)
        check_protocols = inputs.get('check_protocols', True)
        check_vulns = inputs.get('check_vulnerabilities', True)
        timeout = inputs.get('timeout', 10)
        
        results = {
            'target': f"{target_host}:{target_port}",
            'certificate': {},
            'cipher_analysis': {},
            'protocol_analysis': {},
            'vulnerabilities': [],
            'security_score': 0
        }
        
        try:
            # Certificate analysis
            if check_cert_chain:
                cert_info = self.get_certificate_info(target_host, target_port, timeout)
                results['certificate'] = cert_info
            
            # Cipher suite analysis
            cipher_info = {}
            if check_ciphers:
                cipher_info = self.test_cipher_suites(target_host, target_port, timeout)
                results['cipher_analysis'] = cipher_info
            
            # Protocol analysis
            protocol_info = {}
            if check_protocols:
                protocol_info = self.test_ssl_protocols(target_host, target_port, timeout)
                results['protocol_analysis'] = protocol_info
            
            # Vulnerability check
            if check_vulns:
                vulns = self.check_ssl_vulnerabilities(target_host, target_port, cipher_info, protocol_info)
                results['vulnerabilities'] = vulns
            
            # Calculate security score
            score = 100
            
            # Deduct points for issues
            if results.get('certificate', {}).get('is_expired'):
                score -= 30
            if results.get('certificate', {}).get('is_self_signed'):
                score -= 20
            if results.get('certificate', {}).get('days_to_expiry', 365) < 30:
                score -= 10
            
            deprecated_protocols = protocol_info.get('deprecated_protocols', [])
            score -= len(deprecated_protocols) * 15
            
            weak_ciphers = cipher_info.get('weak_ciphers', [])
            score -= len(weak_ciphers) * 10
            
            vulns = results.get('vulnerabilities', [])
            for vuln in vulns:
                if vuln['severity'] == 'high':
                    score -= 25
                elif vuln['severity'] == 'medium':
                    score -= 15
                elif vuln['severity'] == 'low':
                    score -= 5
            
            results['security_score'] = max(0, score)
            
            # Generate summary
            results['summary'] = {
                'total_issues': len(vulns),
                'certificate_valid': results.get('certificate', {}).get('is_valid', False),
                'strong_protocols_only': len(deprecated_protocols) == 0,
                'strong_ciphers_available': len(cipher_info.get('strong_ciphers', [])) > 0,
                'security_grade': self._get_security_grade(results['security_score'])
            }
            
            self.update_progress("SSL/TLS analysis completed", 100)
            
        except Exception as e:
            self.logger.error(f"SSL/TLS analysis error: {e}")
            results['error'] = str(e)
        
        return results

    def _get_security_grade(self, score: int) -> str:
        """Convert security score to letter grade."""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

    def stop_scan(self):
        """Stop the SSL/TLS analysis."""
        self.logger.info("SSL/TLS analysis stop requested")
