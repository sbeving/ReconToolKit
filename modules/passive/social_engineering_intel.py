"""
Social Engineering Intelligence Module
Advanced social engineering intelligence gathering and analysis.
"""

import asyncio
import logging
import json
import re
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import aiohttp
import whois
from bs4 import BeautifulSoup
import dns.resolver
from email_validator import validate_email, EmailNotValidError

from modules.base_module import BaseModule


class SocialEngineeringIntelModule(BaseModule):
    """Advanced social engineering intelligence gathering module."""
    
    def __init__(self):
        """Initialize the social engineering intelligence module."""
        super().__init__(
            name="Social Engineering Intelligence",
            description="Advanced social engineering intelligence gathering and analysis",
            category="passive"
        )
        self.author = "ReconToolKit Team"
        self.version = "1.0.0"
        
        # Initialize configurations
        self.timeout = 30
        self.max_concurrent = 10
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Social media platforms
        self.social_platforms = {
            'linkedin': 'https://www.linkedin.com/company/{}',
            'twitter': 'https://twitter.com/{}',
            'facebook': 'https://www.facebook.com/{}',
            'instagram': 'https://www.instagram.com/{}',
            'github': 'https://github.com/{}',
            'youtube': 'https://www.youtube.com/c/{}',
            'crunchbase': 'https://www.crunchbase.com/organization/{}'
        }
        
        # Common email patterns
        self.email_patterns = [
            '{first}.{last}@{domain}',
            '{first}{last}@{domain}',
            '{first}@{domain}',
            '{last}@{domain}',
            '{first_initial}{last}@{domain}',
            '{first}{last_initial}@{domain}',
            '{first_initial}.{last}@{domain}',
            '{first}.{last_initial}@{domain}'
        ]
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """Get configuration fields for the module."""
        return [
            {
                'name': 'target_domain',
                'label': 'Target Domain',
                'type': 'text',
                'required': True,
                'placeholder': 'example.com',
                'help': 'Target domain for social engineering intelligence'
            },
            {
                'name': 'company_name',
                'label': 'Company Name',
                'type': 'text',
                'required': False,
                'placeholder': 'Example Corp',
                'help': 'Company name for social media analysis'
            },
            {
                'name': 'include_employees',
                'label': 'Include Employee Search',
                'type': 'checkbox',
                'default': True,
                'help': 'Search for company employees on social platforms'
            },
            {
                'name': 'include_breaches',
                'label': 'Check Data Breaches',
                'type': 'checkbox',
                'default': True,
                'help': 'Check for domain in known data breaches'
            },
            {
                'name': 'generate_emails',
                'label': 'Generate Email Patterns',
                'type': 'checkbox',
                'default': True,
                'help': 'Generate potential email addresses'
            },
            {
                'name': 'social_platforms',
                'label': 'Social Platforms',
                'type': 'multiselect',
                'options': list(self.social_platforms.keys()),
                'default': ['linkedin', 'twitter', 'github'],
                'help': 'Social media platforms to search'
            }
        ]
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run social engineering intelligence gathering.
        
        Args:
            inputs: User inputs from the form
            config: Module configuration
            
        Returns:
            Dictionary containing intelligence results
        """
        try:
            target_domain = inputs.get('target_domain', '')
            self.logger.info(f"Starting social engineering intelligence for {target_domain}")
            
            results = {
                'target_domain': target_domain,
                'company_name': inputs.get('company_name', ''),
                'timestamp': time.time(),
                'domain_info': {},
                'social_presence': {},
                'email_patterns': [],
                'summary': f"Social engineering intelligence analysis completed for {target_domain}"
            }
            
            # Basic domain analysis (simplified for now)
            try:
                import socket
                ip = socket.gethostbyname(target_domain)
                results['domain_info']['ip_address'] = ip
                results['domain_info']['resolved'] = True
            except:
                results['domain_info']['resolved'] = False
                results['domain_info']['error'] = 'Domain resolution failed'
            
            # Generate basic email patterns
            if inputs.get('generate_emails', True):
                domain = target_domain
                common_prefixes = ['info', 'contact', 'admin', 'support', 'sales', 'marketing']
                email_patterns = [f"{prefix}@{domain}" for prefix in common_prefixes]
                results['email_patterns'] = email_patterns
            
            self.logger.info(f"Social engineering intelligence completed for {target_domain}")
            return results
            
        except Exception as e:
            error_msg = f"Error in social engineering intelligence: {str(e)}"
            self.logger.error(error_msg)
            return {
                'error': error_msg,
                'target_domain': inputs.get('target_domain', ''),
                'timestamp': time.time()
            }
    
    async def _gather_domain_info(self, domain: str, results: Dict[str, Any], session: aiohttp.ClientSession):
        """Gather basic domain information."""
        try:
            # WHOIS information
            try:
                whois_info = whois.whois(domain)
                results['domain_info']['whois'] = {
                    'registrar': str(whois_info.registrar) if whois_info.registrar else None,
                    'creation_date': str(whois_info.creation_date) if whois_info.creation_date else None,
                    'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else None,
                    'name_servers': whois_info.name_servers if whois_info.name_servers else [],
                    'organization': str(whois_info.org) if hasattr(whois_info, 'org') and whois_info.org else None
                }
            except Exception as e:
                self.logger.warning(f"Could not retrieve WHOIS info: {e}")
                results['domain_info']['whois'] = {'error': str(e)}
            
            # DNS records
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(answer) for answer in answers]
                except Exception:
                    dns_records[record_type] = []
            
            results['domain_info']['dns'] = dns_records
            
            # Website information
            try:
                async with session.get(f'http://{domain}', allow_redirects=True) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        results['domain_info']['website'] = {
                            'title': soup.title.string if soup.title else None,
                            'description': self._extract_meta_content(soup, 'description'),
                            'keywords': self._extract_meta_content(soup, 'keywords'),
                            'technologies': self._detect_technologies(response.headers, html),
                            'social_links': self._extract_social_links(soup)
                        }
            except Exception as e:
                self.logger.warning(f"Could not retrieve website info: {e}")
                results['domain_info']['website'] = {'error': str(e)}
                
        except Exception as e:
            self.logger.error(f"Error gathering domain info: {e}")
            results['domain_info']['error'] = str(e)
    
    async def _analyze_social_presence(self, config: Dict[str, Any], results: Dict[str, Any], session: aiohttp.ClientSession):
        """Analyze social media presence."""
        company_name = config.get('company_name', '').replace(' ', '').lower()
        domain = config['target_domain'].split('.')[0]
        
        search_terms = [company_name, domain] if company_name else [domain]
        platforms = config.get('social_platforms', [])
        
        for platform in platforms:
            if platform in self.social_platforms:
                platform_results = []
                
                for term in search_terms:
                    if term:
                        try:
                            url = self.social_platforms[platform].format(term)
                            async with session.get(url, allow_redirects=True) as response:
                                if response.status == 200:
                                    platform_results.append({
                                        'url': url,
                                        'status': 'found',
                                        'search_term': term
                                    })
                                else:
                                    platform_results.append({
                                        'url': url,
                                        'status': 'not_found',
                                        'search_term': term
                                    })
                        except Exception as e:
                            platform_results.append({
                                'url': self.social_platforms[platform].format(term),
                                'status': 'error',
                                'error': str(e),
                                'search_term': term
                            })
                
                results['social_presence'][platform] = platform_results
    
    async def _gather_employee_intelligence(self, config: Dict[str, Any], results: Dict[str, Any], session: aiohttp.ClientSession):
        """Gather employee intelligence from various sources."""
        company_name = config.get('company_name', '')
        domain = config['target_domain']
        
        # LinkedIn search simulation (note: actual LinkedIn API requires authentication)
        linkedin_intel = {
            'search_performed': True,
            'company_name': company_name,
            'estimated_employees': 'API_REQUIRED',
            'note': 'LinkedIn API integration required for actual employee data'
        }
        
        # GitHub organization search
        github_intel = await self._search_github_organization(domain, session)
        
        # Email pattern analysis from DNS/website
        email_intel = await self._analyze_email_patterns(domain, session)
        
        results['employee_intelligence'] = {
            'linkedin': linkedin_intel,
            'github': github_intel,
            'email_analysis': email_intel
        }
    
    async def _search_github_organization(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search for GitHub organization."""
        try:
            org_name = domain.split('.')[0]
            url = f'https://api.github.com/orgs/{org_name}'
            
            async with session.get(url) as response:
                if response.status == 200:
                    org_data = await response.json()
                    return {
                        'found': True,
                        'name': org_data.get('name'),
                        'description': org_data.get('description'),
                        'public_repos': org_data.get('public_repos'),
                        'followers': org_data.get('followers'),
                        'following': org_data.get('following'),
                        'created_at': org_data.get('created_at'),
                        'url': org_data.get('html_url')
                    }
                else:
                    return {'found': False, 'status': response.status}
        except Exception as e:
            return {'found': False, 'error': str(e)}
    
    async def _analyze_email_patterns(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Analyze email patterns from various sources."""
        email_intel = {
            'domain': domain,
            'common_patterns': [],
            'discovered_emails': [],
            'mx_records': []
        }
        
        # MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            email_intel['mx_records'] = [str(mx) for mx in mx_records]
        except Exception:
            email_intel['mx_records'] = []
        
        # Common email patterns
        common_prefixes = ['info', 'contact', 'admin', 'support', 'sales', 'marketing', 'hr']
        for prefix in common_prefixes:
            email = f"{prefix}@{domain}"
            email_intel['common_patterns'].append(email)
        
        return email_intel
    
    async def _generate_email_patterns(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Generate potential email patterns."""
        domain = config['target_domain']
        
        # Common name combinations
        common_names = [
            ('john', 'doe'), ('jane', 'smith'), ('mike', 'johnson'),
            ('sarah', 'williams'), ('david', 'brown'), ('lisa', 'davis')
        ]
        
        email_patterns = []
        for first, last in common_names:
            for pattern in self.email_patterns:
                email = pattern.format(
                    first=first,
                    last=last,
                    domain=domain,
                    first_initial=first[0],
                    last_initial=last[0]
                )
                email_patterns.append(email)
        
        results['email_patterns'] = email_patterns[:50]  # Limit to first 50
    
    async def _check_breach_data(self, domain: str, results: Dict[str, Any], session: aiohttp.ClientSession):
        """Check for domain in known data breaches."""
        # This would integrate with HaveIBeenPwned API or similar services
        # Note: Actual implementation requires API keys and proper rate limiting
        
        breach_info = {
            'checked': True,
            'domain': domain,
            'note': 'Breach checking requires HaveIBeenPwned API integration',
            'recommendations': [
                'Integrate with HaveIBeenPwned API for real breach data',
                'Monitor for new breaches involving the domain',
                'Implement breach notification system'
            ]
        }
        
        results['breach_data'] = breach_info
    
    async def _analyze_organization(self, config: Dict[str, Any], results: Dict[str, Any], session: aiohttp.ClientSession):
        """Analyze organization information."""
        company_name = config.get('company_name', '')
        domain = config['target_domain']
        
        org_info = {
            'company_name': company_name,
            'domain': domain,
            'industry_analysis': await self._analyze_industry(domain, session),
            'technology_stack': results['domain_info'].get('website', {}).get('technologies', []),
            'business_intelligence': {
                'note': 'Business intelligence gathering would integrate with:'
                'Crunchbase API, SEC filings, news APIs, etc.'
            }
        }
        
        results['organization_info'] = org_info
    
    async def _analyze_industry(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Analyze industry information."""
        return {
            'domain': domain,
            'analysis_method': 'website_content_analysis',
            'note': 'Industry analysis would use ML/NLP on website content',
            'suggested_integrations': [
                'Industry classification APIs',
                'Business directory APIs',
                'Machine learning content analysis'
            ]
        }
    
    def _extract_meta_content(self, soup: BeautifulSoup, name: str) -> str:
        """Extract meta tag content."""
        meta = soup.find('meta', attrs={'name': name}) or soup.find('meta', attrs={'property': f'og:{name}'})
        return meta.get('content', '') if meta else ''
    
    def _detect_technologies(self, headers: Dict[str, str], html: str) -> List[str]:
        """Detect technologies used by the website."""
        technologies = []
        
        # Server detection
        server = headers.get('server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # Framework detection from HTML
        if 'wp-content' in html:
            technologies.append('WordPress')
        if 'drupal' in html.lower():
            technologies.append('Drupal')
        if 'joomla' in html.lower():
            technologies.append('Joomla')
        if 'react' in html.lower():
            technologies.append('React')
        if 'angular' in html.lower():
            technologies.append('Angular')
        if 'vue' in html.lower():
            technologies.append('Vue.js')
        
        return technologies
    
    def _extract_social_links(self, soup: BeautifulSoup) -> List[str]:
        """Extract social media links from website."""
        social_links = []
        social_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com']
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            for social_domain in social_domains:
                if social_domain in href:
                    social_links.append(href)
                    break
        
        return list(set(social_links))  # Remove duplicates
    
    def _generate_recommendations(self, results: Dict[str, Any]):
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Domain recommendations
        if results.get('domain_info', {}).get('whois', {}).get('expiration_date'):
            recommendations.append({
                'category': 'Domain Security',
                'recommendation': 'Monitor domain expiration dates to prevent hijacking',
                'priority': 'medium'
            })
        
        # Social media recommendations
        if results.get('social_presence'):
            found_platforms = [p for p, data in results['social_presence'].items() 
                             if any(d.get('status') == 'found' for d in data)]
            if found_platforms:
                recommendations.append({
                    'category': 'Social Media Security',
                    'recommendation': f'Monitor social media presence on: {", ".join(found_platforms)}',
                    'priority': 'low'
                })
        
        # Email security recommendations
        if results.get('email_patterns'):
            recommendations.append({
                'category': 'Email Security',
                'recommendation': 'Implement email security measures (SPF, DKIM, DMARC)',
                'priority': 'high'
            })
        
        # Employee security recommendations
        if results.get('employee_intelligence'):
            recommendations.append({
                'category': 'Employee Security',
                'recommendation': 'Conduct security awareness training for social engineering threats',
                'priority': 'high'
            })
        
        results['recommendations'] = recommendations
    
    def cleanup(self):
        """Clean up module resources."""
        pass


# Create module instance
module = SocialEngineeringIntelModule()
