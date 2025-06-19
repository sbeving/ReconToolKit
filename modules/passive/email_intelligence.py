"""
Email Intelligence Module
Advanced email intelligence gathering and breach detection.
"""

import logging
import asyncio
import aiohttp
import re
import time
import hashlib
from typing import Dict, Any, List, Optional
from urllib.parse import quote, urljoin
from modules.base_module import BaseModule


class EmailIntelligenceModule(BaseModule):
    """Advanced email intelligence and breach detection module."""
    
    def __init__(self):
        super().__init__(
            name="Email Intelligence",
            description="Comprehensive email intelligence gathering including breach detection, domain analysis, and email validation",
            category="passive"
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Email validation regex
        self.email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        # Common email providers
        self.email_providers = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'hotmail.com': 'Microsoft Hotmail',
            'outlook.com': 'Microsoft Outlook',
            'live.com': 'Microsoft Live',
            'protonmail.com': 'ProtonMail',
            'tutanota.com': 'Tutanota',
            'icloud.com': 'Apple iCloud',
            'aol.com': 'AOL Mail',
            'mail.com': 'Mail.com'
        }
        
        # Breach detection APIs (placeholder URLs)
        self.breach_apis = {
            'haveibeenpwned': 'https://haveibeenpwned.com/api/v3/breachedaccount/',
            'dehashed': 'https://api.dehashed.com/search',
            'leakcheck': 'https://api.leakcheck.io/v2/query/'
        }

    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'target_email',
                'type': 'text',
                'label': 'Target Email Address',
                'required': True,
                'default': '',
                'placeholder': 'user@example.com'
            },
            {
                'name': 'check_breaches',
                'type': 'checkbox',
                'label': 'Check Data Breaches',
                'required': False,
                'default': True
            },
            {
                'name': 'validate_email',
                'type': 'checkbox',
                'label': 'Email Validation',
                'required': False,
                'default': True
            },
            {
                'name': 'domain_analysis',
                'type': 'checkbox',
                'label': 'Domain Analysis',
                'required': False,
                'default': True
            },
            {
                'name': 'social_media_search',
                'type': 'checkbox',
                'label': 'Social Media Search',
                'required': False,
                'default': True
            },
            {
                'name': 'generate_variations',
                'type': 'checkbox',
                'label': 'Generate Email Variations',
                'required': False,
                'default': True
            },
            {
                'name': 'custom_domains',
                'type': 'text',
                'label': 'Additional Domains to Check',
                'required': False,
                'default': '',
                'placeholder': 'company.com,subsidiary.com'
            },
            {
                'name': 'deep_search',
                'type': 'checkbox',
                'label': 'Deep Search (Slower)',
                'required': False,
                'default': False,
                'tooltip': 'More comprehensive but slower analysis'
            }
        ]

    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        target_email = inputs.get('target_email', '').strip()
        if not target_email:
            return "Target email address is required"
        
        if not self.email_regex.match(target_email):
            return "Invalid email address format"
        
        return None

    def extract_email_parts(self, email: str) -> Dict[str, str]:
        """Extract username and domain from email."""
        username, domain = email.split('@', 1)
        return {
            'username': username,
            'domain': domain,
            'tld': domain.split('.')[-1] if '.' in domain else '',
            'subdomain': '.'.join(domain.split('.')[:-2]) if domain.count('.') > 1 else ''
        }

    async def validate_email_address(self, session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
        """Validate email address using various methods."""
        self.update_progress("Validating email address...", 20)
        
        validation_result = {
            'email': email,
            'is_valid_format': self.email_regex.match(email) is not None,
            'domain_exists': False,
            'mx_records': [],
            'disposable': False,
            'role_account': False,
            'provider': 'unknown'
        }
        
        email_parts = self.extract_email_parts(email)
        domain = email_parts['domain']
        
        # Check if it's a known provider
        if domain in self.email_providers:
            validation_result['provider'] = self.email_providers[domain]
        
        # Check for role accounts
        role_keywords = ['admin', 'support', 'info', 'contact', 'sales', 'marketing', 'hr', 'help']
        validation_result['role_account'] = any(keyword in email_parts['username'].lower() for keyword in role_keywords)
        
        # Check for disposable email providers
        disposable_domains = [
            '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
            'yopmail.com', 'throwaway.email', 'maildrop.cc'
        ]
        validation_result['disposable'] = domain in disposable_domains
        
        try:
            # Try to get MX records (simplified check)
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            validation_result['domain_exists'] = True
            validation_result['mx_records'] = [str(mx) for mx in mx_records]
        except Exception:
            validation_result['domain_exists'] = False
        
        return validation_result

    async def check_data_breaches(self, session: aiohttp.ClientSession, email: str) -> List[Dict[str, Any]]:
        """Check if email appears in known data breaches."""
        self.update_progress("Checking data breaches...", 40)
        
        breaches = []
        
        # Note: This is a simplified implementation
        # In a real implementation, you would need API keys and proper authentication
        
        try:
            # Simulate HaveIBeenPwned API call (would need proper API key)
            # For demonstration, we'll return mock data
            mock_breaches = [
                {
                    'source': 'HaveIBeenPwned',
                    'breach_name': 'Example Breach 2020',
                    'breach_date': '2020-03-15',
                    'data_types': ['email', 'password', 'username'],
                    'verified': True,
                    'severity': 'high'
                }
            ]
            
            # In real implementation, check against actual APIs
            # breaches.extend(mock_breaches)
            
        except Exception as e:
            self.logger.error(f"Error checking breaches: {e}")
        
        return breaches

    async def analyze_domain(self, session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
        """Analyze the email domain for additional intelligence."""
        self.update_progress("Analyzing domain...", 60)
        
        domain_info = {
            'domain': domain,
            'is_corporate': False,
            'technology_stack': [],
            'social_presence': {},
            'subdomains_found': [],
            'security_headers': {}
        }
        
        try:
            # Check if it's a corporate domain (not a free email provider)
            domain_info['is_corporate'] = domain not in self.email_providers
            
            # Try to get technology information from headers
            try:
                async with session.get(f"https://{domain}", timeout=aiohttp.ClientTimeout(total=10)) as response:
                    headers = dict(response.headers)
                    
                    # Extract technology information
                    server_header = headers.get('Server', '')
                    powered_by = headers.get('X-Powered-By', '')
                    
                    if server_header:
                        domain_info['technology_stack'].append(f"Server: {server_header}")
                    if powered_by:
                        domain_info['technology_stack'].append(f"Powered-By: {powered_by}")
                    
                    # Check security headers
                    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
                    for header in security_headers:
                        if header in headers:
                            domain_info['security_headers'][header] = headers[header]
                            
            except Exception:
                pass
            
            # Common subdomain check
            common_subdomains = ['www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'api', 'app']
            for subdomain in common_subdomains:
                try:
                    test_domain = f"{subdomain}.{domain}"
                    async with session.get(f"https://{test_domain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            domain_info['subdomains_found'].append(test_domain)
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error analyzing domain: {e}")
        
        return domain_info

    def generate_email_variations(self, email: str, custom_domains: List[str] = None) -> List[str]:
        """Generate possible email variations."""
        self.update_progress("Generating email variations...", 80)
        
        email_parts = self.extract_email_parts(email)
        username = email_parts['username']
        original_domain = email_parts['domain']
        
        variations = []
        
        # Username variations
        username_variations = [
            username,
            username.replace('.', ''),
            username.replace('_', '.'),
            username.replace('-', '.'),
            username.replace('.', '_'),
            username.replace('-', '_'),
        ]
        
        # Add first.last variations if username contains separators
        if '.' in username:
            parts = username.split('.')
            if len(parts) == 2:
                username_variations.extend([
                    f"{parts[0]}{parts[1]}",
                    f"{parts[0]}_{parts[1]}",
                    f"{parts[0]}-{parts[1]}",
                    f"{parts[1]}.{parts[0]}",
                    f"{parts[1]}_{parts[0]}",
                    f"{parts[1]}-{parts[0]}"
                ])
        
        # Domain variations
        domains_to_check = [original_domain]
        
        if custom_domains:
            domains_to_check.extend(custom_domains)
        
        # Add common corporate domain patterns
        if '.' in original_domain:
            domain_parts = original_domain.split('.')
            if len(domain_parts) >= 2:
                base_domain = domain_parts[-2]
                tld = domain_parts[-1]
                
                # Common variations
                domains_to_check.extend([
                    f"{base_domain}.com",
                    f"{base_domain}.org",
                    f"{base_domain}.net",
                    f"mail.{original_domain}",
                    f"email.{original_domain}"
                ])
        
        # Generate all combinations
        for username_var in username_variations:
            for domain_var in domains_to_check:
                variation = f"{username_var}@{domain_var}"
                if variation != email and variation not in variations:
                    variations.append(variation)
        
        return variations[:50]  # Limit to 50 variations

    async def search_social_media(self, session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
        """Search for social media presence (simplified implementation)."""
        
        social_results = {
            'platforms_found': [],
            'profiles': {},
            'confidence_score': 0
        }
        
        # Note: This is a simplified implementation
        # Real social media searching would require API access and proper rate limiting
        
        email_parts = self.extract_email_parts(email)
        username = email_parts['username']
        
        # Common social media platforms to check
        platforms = {
            'twitter': f"https://twitter.com/{username}",
            'linkedin': f"https://linkedin.com/in/{username}",
            'github': f"https://github.com/{username}",
            'instagram': f"https://instagram.com/{username}"
        }
        
        for platform, url in platforms.items():
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        social_results['platforms_found'].append(platform)
                        social_results['profiles'][platform] = url
            except Exception:
                continue
        
        social_results['confidence_score'] = len(social_results['platforms_found']) * 25
        return social_results

    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run the email intelligence scan."""
        target_email = inputs.get('target_email').strip().lower()
        check_breaches = inputs.get('check_breaches', True)
        validate_email = inputs.get('validate_email', True)
        domain_analysis = inputs.get('domain_analysis', True)
        social_media_search = inputs.get('social_media_search', True)
        generate_variations = inputs.get('generate_variations', True)
        custom_domains = inputs.get('custom_domains', '').strip()
        deep_search = inputs.get('deep_search', False)
        
        start_time = time.time()
        
        # Parse custom domains
        custom_domain_list = [d.strip() for d in custom_domains.split(',') if d.strip()] if custom_domains else []
        
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                self._run_async_email_scan(
                    target_email, check_breaches, validate_email, domain_analysis,
                    social_media_search, generate_variations, custom_domain_list, deep_search
                )
            )
        finally:
            loop.close()
        
        scan_time = time.time() - start_time
        
        # Generate summary
        email_parts = self.extract_email_parts(target_email)
        
        results['summary'] = {
            'target_email': target_email,
            'username': email_parts['username'],
            'domain': email_parts['domain'],
            'scan_time': round(scan_time, 2),
            'breaches_found': len(results.get('breaches', [])),
            'variations_generated': len(results.get('email_variations', [])),
            'social_platforms_found': len(results.get('social_media', {}).get('platforms_found', [])),
            'domain_is_corporate': results.get('domain_analysis', {}).get('is_corporate', False),
            'email_is_valid': results.get('validation', {}).get('is_valid_format', False),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return results

    async def _run_async_email_scan(self, target_email: str, check_breaches: bool, 
                                  validate_email: bool, domain_analysis: bool,
                                  social_media_search: bool, generate_variations: bool,
                                  custom_domains: List[str], deep_search: bool) -> Dict[str, Any]:
        """Run the async email intelligence scan."""
        
        connector = aiohttp.TCPConnector(limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.get_user_agent()}
        ) as session:
            
            results = {
                'target_email': target_email,
                'validation': {},
                'breaches': [],
                'domain_analysis': {},
                'social_media': {},
                'email_variations': []
            }
            
            email_parts = self.extract_email_parts(target_email)
            
            # Email validation
            if validate_email:
                results['validation'] = await self.validate_email_address(session, target_email)
            
            # Breach detection
            if check_breaches:
                results['breaches'] = await self.check_data_breaches(session, target_email)
            
            # Domain analysis
            if domain_analysis:
                results['domain_analysis'] = await self.analyze_domain(session, email_parts['domain'])
            
            # Social media search
            if social_media_search:
                results['social_media'] = await self.search_social_media(session, target_email)
            
            # Email variations
            if generate_variations:
                results['email_variations'] = self.generate_email_variations(target_email, custom_domains)
            
            self.update_progress("Email intelligence scan completed", 100)
            return results

    def stop_scan(self):
        """Stop the email intelligence scan."""
        self.logger.info("Email intelligence scan stop requested")
