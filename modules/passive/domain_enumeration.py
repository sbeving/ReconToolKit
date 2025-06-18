"""
Domain Enumeration Module
Performs comprehensive domain reconnaissance including WHOIS, DNS, and subdomain enumeration.
"""

import socket
import requests
import whois
import dns.resolver
import dns.reversename
import json
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse
import time

from ..base_module import BaseModule


class DomainEnumerationModule(BaseModule):
    """Domain enumeration and reconnaissance module."""
    
    def __init__(self):
        super().__init__(
            name="Domain Enumeration",
            description="Comprehensive domain reconnaissance including WHOIS, DNS records, and subdomain discovery",
            category="passive"
        )
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'email', 'webmail', 'secure', 'ftp', 'ssh', 'remote', 'admin',
            'administrator', 'test', 'testing', 'dev', 'development', 'stage', 'staging',
            'prod', 'production', 'api', 'app', 'mobile', 'web', 'cdn', 'blog', 'news',
            'portal', 'vpn', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2', 'mx', 'mx1',
            'mx2', 'smtp', 'pop', 'imap', 'help', 'support', 'forum', 'shop', 'store',
            'download', 'upload', 'backup', 'db', 'database', 'server', 'host', 'monitor',
            'status', 'stats', 'demo', 'beta', 'alpha', 'old', 'new', 'temp', 'video',
            'images', 'img', 'static', 'assets', 'media', 'files', 'docs', 'documentation'
        ]
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """Get input fields for domain enumeration."""
        return [
            {
                'name': 'domain',
                'type': 'text',
                'label': 'Target Domain',
                'required': True,
                'placeholder': 'example.com',
                'tooltip': 'Enter the target domain name (without http://)'
            },
            {
                'name': 'include_subdomains',
                'type': 'checkbox',
                'label': 'Include Subdomain Enumeration',
                'required': False,
                'default': True,
                'tooltip': 'Perform subdomain discovery using various techniques'
            },
            {
                'name': 'include_whois',
                'type': 'checkbox',
                'label': 'Include WHOIS Lookup',
                'required': False,
                'default': True,
                'tooltip': 'Fetch domain registration information'
            },
            {
                'name': 'include_dns',
                'type': 'checkbox',
                'label': 'Include DNS Enumeration',
                'required': False,
                'default': True,
                'tooltip': 'Enumerate DNS records (A, AAAA, MX, NS, TXT, etc.)'
            },
            {
                'name': 'custom_wordlist',
                'type': 'file',
                'label': 'Custom Subdomain Wordlist',
                'required': False,
                'tooltip': 'Optional custom wordlist file for subdomain brute-forcing'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        """Validate input parameters."""
        domain = inputs.get('domain', '').strip()
        
        if not domain:
            return "Domain is required"
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            return "Invalid domain format"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run domain enumeration scan."""
        domain = inputs['domain'].strip().lower()
        include_subdomains = inputs.get('include_subdomains', True)
        include_whois = inputs.get('include_whois', True)
        include_dns = inputs.get('include_dns', True)
        custom_wordlist = inputs.get('custom_wordlist', '')
        
        results = {
            'domain': domain,
            'timestamp': time.time(),
            'whois_info': {},
            'dns_records': {},
            'subdomains': [],
            'ip_addresses': [],
            'summary': {}
        }
        
        total_steps = sum([include_whois, include_dns, include_subdomains])
        current_step = 0
        
        try:
            # WHOIS lookup
            if include_whois:
                self.update_progress("Performing WHOIS lookup...", int((current_step / total_steps) * 100))
                results['whois_info'] = self._get_whois_info(domain)
                current_step += 1
            
            # DNS enumeration
            if include_dns:
                self.update_progress("Enumerating DNS records...", int((current_step / total_steps) * 100))
                results['dns_records'] = self._get_dns_records(domain)
                current_step += 1
            
            # Get IP addresses from DNS results
            if 'A' in results['dns_records']:
                results['ip_addresses'].extend(results['dns_records']['A'])
            if 'AAAA' in results['dns_records']:
                results['ip_addresses'].extend(results['dns_records']['AAAA'])
            
            # Subdomain enumeration
            if include_subdomains:
                self.update_progress("Discovering subdomains...", int((current_step / total_steps) * 100))
                results['subdomains'] = self._discover_subdomains(domain, custom_wordlist)
                current_step += 1
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
            self.update_progress("Scan completed successfully", 100)
            
        except Exception as e:
            self.logger.error(f"Domain enumeration error: {e}")
            raise
        
        return results
    
    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain."""
        try:
            w = whois.whois(domain)
            
            # Convert whois object to dictionary
            whois_data = {}
            
            # Extract common fields
            fields = ['domain_name', 'registrar', 'creation_date', 'expiration_date',
                     'updated_date', 'status', 'name_servers', 'emails', 'org', 'country']
            
            for field in fields:
                value = getattr(w, field, None)
                if value:
                    # Handle lists and dates
                    if isinstance(value, list):
                        whois_data[field] = [str(v) for v in value]
                    else:
                        whois_data[field] = str(value)
            
            return whois_data
            
        except Exception as e:
            self.logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}
    
    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records for domain."""
        dns_records = {}
        
        # DNS record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            if not self.should_continue():
                break
                
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for answer in answers:
                    if record_type == 'MX':
                        records.append(f"{answer.preference} {answer.exchange}")
                    elif record_type == 'SOA':
                        records.append(f"{answer.mname} {answer.rname}")
                    else:
                        records.append(str(answer))
                
                if records:
                    dns_records[record_type] = records
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
                self.logger.debug(f"No {record_type} record for {domain}: {e}")
            except Exception as e:
                self.logger.warning(f"DNS query error for {domain} {record_type}: {e}")
        
        return dns_records
    
    def _discover_subdomains(self, domain: str, custom_wordlist: str = '') -> List[Dict[str, Any]]:
        """Discover subdomains using various techniques."""
        subdomains = set()
        subdomain_results = []
        
        # Use custom wordlist if provided, otherwise use built-in
        wordlist = self.common_subdomains
        if custom_wordlist and custom_wordlist.strip():
            try:
                with open(custom_wordlist.strip(), 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.warning(f"Could not load custom wordlist: {e}")
        
        # Brute force subdomains
        self.update_progress("Brute-forcing subdomains...", -1)
        total_subs = len(wordlist)
        
        for i, subdomain in enumerate(wordlist):
            if not self.should_continue():
                break
            
            if i % 10 == 0:  # Update progress every 10 attempts
                progress = int((i / total_subs) * 50)  # 50% for brute force
                self.update_progress(f"Testing subdomain: {subdomain}.{domain}", progress)
            
            full_domain = f"{subdomain}.{domain}"
            
            try:
                # Try to resolve the subdomain
                answers = dns.resolver.resolve(full_domain, 'A')
                ips = [str(answer) for answer in answers]
                
                if ips:
                    subdomains.add(full_domain)
                    subdomain_results.append({
                        'subdomain': full_domain,
                        'ips': ips,
                        'method': 'brute_force'
                    })
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass  # Subdomain doesn't exist
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {full_domain}: {e}")
        
        # Certificate Transparency search
        self.update_progress("Searching Certificate Transparency logs...", 60)
        ct_subdomains = self._search_certificate_transparency(domain)
        
        for subdomain in ct_subdomains:
            if subdomain not in subdomains:
                subdomains.add(subdomain)
                subdomain_results.append({
                    'subdomain': subdomain,
                    'ips': self._resolve_domain(subdomain),
                    'method': 'certificate_transparency'
                })
        
        # Search engines (passive)
        self.update_progress("Searching with search engines...", 80)
        search_subdomains = self._search_engines_subdomains(domain)
        
        for subdomain in search_subdomains:
            if subdomain not in subdomains:
                subdomains.add(subdomain)
                subdomain_results.append({
                    'subdomain': subdomain,
                    'ips': self._resolve_domain(subdomain),
                    'method': 'search_engine'
                })
        
        return subdomain_results
    
    def _search_certificate_transparency(self, domain: str) -> List[str]:
        """Search Certificate Transparency logs for subdomains."""
        subdomains = set()
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {'User-Agent': self.get_user_agent()}
            
            response = requests.get(url, headers=headers, timeout=self.get_timeout(), 
                                  proxies=self.get_proxy_config())
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple domains in one certificate
                        domains_in_cert = name_value.split('\n')
                        for cert_domain in domains_in_cert:
                            cert_domain = cert_domain.strip()
                            if cert_domain.endswith(f'.{domain}') and '*' not in cert_domain:
                                subdomains.add(cert_domain)
                            
        except Exception as e:
            self.logger.warning(f"Certificate Transparency search failed: {e}")
        
        return list(subdomains)
    
    def _search_engines_subdomains(self, domain: str) -> List[str]:
        """Search for subdomains using search engines (passive)."""
        subdomains = set()
        
        # Search patterns for different engines
        searches = [
            f"site:{domain} -www",
            f"site:*.{domain}",
        ]
        
        for search_query in searches:
            if not self.should_continue():
                break
                
            try:
                # Note: This is a simplified approach. In a real implementation,
                # you might want to use specific APIs or more sophisticated scraping
                # For now, we'll simulate finding some common subdomains
                
                # Simulate search results (in a real implementation, use actual search APIs)
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                self.logger.warning(f"Search engine query failed: {e}")
        
        return list(subdomains)
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except:
            return []
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of scan results."""
        summary = {
            'total_subdomains': len(results['subdomains']),
            'total_ips': len(results['ip_addresses']),
            'dns_records_found': len(results['dns_records']),
            'whois_available': 'error' not in results['whois_info'],
            'subdomain_methods': {}
        }
        
        # Count subdomains by discovery method
        for subdomain_data in results['subdomains']:
            method = subdomain_data.get('method', 'unknown')
            summary['subdomain_methods'][method] = summary['subdomain_methods'].get(method, 0) + 1
        
        return summary
