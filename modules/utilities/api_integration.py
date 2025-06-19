"""
API Integration Module
Integrates with external APIs and services for enhanced reconnaissance.
"""

import logging
import asyncio
import json
import time
import base64
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import aiohttp
import requests
from urllib.parse import quote, urljoin
from modules.base_module import BaseModule


class APIProvider:
    """Base class for API providers."""
    
    def __init__(self, name: str, base_url: str, api_key: str = "", rate_limit: int = 60):
        self.name = name
        self.base_url = base_url
        self.api_key = api_key
        self.rate_limit = rate_limit  # requests per minute
        self.last_request_time = 0
        self.request_count = 0
        self.enabled = bool(api_key) if api_key else True
    
    async def make_request(self, endpoint: str, method: str = 'GET', 
                          params: Dict[str, Any] = None, data: Dict[str, Any] = None,
                          headers: Dict[str, str] = None) -> Optional[Dict[str, Any]]:
        """Make an API request with rate limiting."""
        if not self.enabled:
            return None
        
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_request_time < 60:  # Within the same minute
            if self.request_count >= self.rate_limit:
                wait_time = 60 - (current_time - self.last_request_time)
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.last_request_time = time.time()
        else:
            self.request_count = 0
            self.last_request_time = current_time
        
        try:
            url = urljoin(self.base_url, endpoint)
            request_headers = self._get_headers()
            if headers:
                request_headers.update(headers)
            
            async with aiohttp.ClientSession() as session:
                if method.upper() == 'GET':
                    async with session.get(url, params=params, headers=request_headers) as response:
                        self.request_count += 1
                        if response.status == 200:
                            return await response.json()
                        else:
                            return {'error': f'HTTP {response.status}', 'status_code': response.status}
                elif method.upper() == 'POST':
                    async with session.post(url, json=data, headers=request_headers) as response:
                        self.request_count += 1
                        if response.status == 200:
                            return await response.json()
                        else:
                            return {'error': f'HTTP {response.status}', 'status_code': response.status}
        
        except Exception as e:
            return {'error': str(e)}
    
    def _get_headers(self) -> Dict[str, str]:
        """Get default headers including authentication."""
        headers = {
            'User-Agent': 'ReconToolKit/1.0.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers.update(self._get_auth_headers())
        
        return headers
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers. Override in subclasses."""
        return {}


class ShodanProvider(APIProvider):
    """Shodan API provider."""
    
    def __init__(self, api_key: str = ""):
        super().__init__("Shodan", "https://api.shodan.io", api_key, 120)  # 120 requests/minute
    
    def _get_auth_headers(self) -> Dict[str, str]:
        return {}  # Shodan uses key parameter
    
    async def search_hosts(self, query: str, limit: int = 100) -> Optional[Dict[str, Any]]:
        """Search for hosts using Shodan."""
        params = {
            'key': self.api_key,
            'query': query,
            'limit': min(limit, 100)
        }
        return await self.make_request('/shodan/host/search', params=params)
    
    async def get_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a host."""
        params = {'key': self.api_key}
        return await self.make_request(f'/shodan/host/{ip}', params=params)


class VirusTotalProvider(APIProvider):
    """VirusTotal API provider."""
    
    def __init__(self, api_key: str = ""):
        super().__init__("VirusTotal", "https://www.virustotal.com/api/v3", api_key, 60)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        return {'x-apikey': self.api_key}
    
    async def analyze_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Analyze a URL with VirusTotal."""
        # First submit the URL
        data = {'url': url}
        response = await self.make_request('/urls', method='POST', data=data)
        
        if response and 'data' in response:
            analysis_id = response['data']['id']
            # Wait a bit and then get results
            await asyncio.sleep(2)
            return await self.make_request(f'/analyses/{analysis_id}')
        
        return response
    
    async def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain information from VirusTotal."""
        return await self.make_request(f'/domains/{domain}')
    
    async def get_ip_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get IP information from VirusTotal."""
        return await self.make_request(f'/ip_addresses/{ip}')


class CensysProvider(APIProvider):
    """Censys API provider."""
    
    def __init__(self, api_id: str = "", api_secret: str = ""):
        super().__init__("Censys", "https://search.censys.io/api/v2", "", 120)
        self.api_id = api_id
        self.api_secret = api_secret
        self.enabled = bool(api_id and api_secret)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        if not self.api_id or not self.api_secret:
            return {}
        
        credentials = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        return {'Authorization': f'Basic {credentials}'}
    
    async def search_hosts(self, query: str, per_page: int = 100) -> Optional[Dict[str, Any]]:
        """Search for hosts using Censys."""
        data = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        return await self.make_request('/hosts/search', method='POST', data=data)
    
    async def get_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a host."""
        return await self.make_request(f'/hosts/{ip}')


class HaveIBeenPwnedProvider(APIProvider):
    """Have I Been Pwned API provider."""
    
    def __init__(self, api_key: str = ""):
        super().__init__("HaveIBeenPwned", "https://haveibeenpwned.com/api/v3", api_key, 10)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        return {'hibp-api-key': self.api_key} if self.api_key else {}
    
    async def check_email_breaches(self, email: str) -> Optional[Dict[str, Any]]:
        """Check if an email has been in any breaches."""
        return await self.make_request(f'/breachedaccount/{quote(email)}')
    
    async def get_all_breaches(self) -> Optional[Dict[str, Any]]:
        """Get all breaches in the system."""
        return await self.make_request('/breaches')


class SecurityTrailsProvider(APIProvider):
    """SecurityTrails API provider."""
    
    def __init__(self, api_key: str = ""):
        super().__init__("SecurityTrails", "https://api.securitytrails.com/v1", api_key, 50)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        return {'APIKEY': self.api_key}
    
    async def get_domain_details(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain details including subdomains."""
        return await self.make_request(f'/domain/{domain}')
    
    async def get_subdomains(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get subdomains for a domain."""
        return await self.make_request(f'/domain/{domain}/subdomains')
    
    async def get_domain_history(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS history for a domain."""
        return await self.make_request(f'/history/{domain}/dns/a')


class APIIntegrationModule(BaseModule):
    """Advanced API integration module for external reconnaissance services."""
    
    def __init__(self):
        super().__init__(
            name="API Integration",
            description="Integrate with external APIs and services for enhanced reconnaissance data",
            category="utilities"
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize API providers
        self.providers = {
            'shodan': ShodanProvider(),
            'virustotal': VirusTotalProvider(),
            'censys': CensysProvider(),
            'haveibeenpwned': HaveIBeenPwnedProvider(),
            'securitytrails': SecurityTrailsProvider()
        }
        
        self.results_cache = {}
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'operation',
                'type': 'combo',
                'label': 'Operation',
                'required': True,
                'default': 'multi_source_lookup',
                'options': [
                    'multi_source_lookup', 'configure_apis', 'test_connections',
                    'shodan_search', 'virustotal_analysis', 'censys_search',
                    'breach_check', 'domain_intelligence', 'ip_intelligence',
                    'bulk_analysis', 'api_status'
                ],
                'tooltip': 'API operation to perform'
            },
            {
                'name': 'target',
                'type': 'text',
                'label': 'Target',
                'required': False,
                'default': '',
                'placeholder': 'IP, domain, URL, or email to analyze'
            },
            {
                'name': 'targets_file',
                'type': 'file',
                'label': 'Targets File',
                'required': False,
                'default': '',
                'tooltip': 'File containing list of targets (one per line)'
            },
            {
                'name': 'search_query',
                'type': 'text',
                'label': 'Search Query',
                'required': False,
                'default': '',
                'placeholder': 'Search query for Shodan/Censys'
            },
            {
                'name': 'api_providers',
                'type': 'multiselect',
                'label': 'API Providers',
                'required': False,
                'default': ['shodan', 'virustotal'],
                'options': list(self.providers.keys()),
                'tooltip': 'Select which API providers to use'
            },
            {
                'name': 'shodan_api_key',
                'type': 'text',
                'label': 'Shodan API Key',
                'required': False,
                'default': '',
                'tooltip': 'Shodan API key for enhanced searches'
            },
            {
                'name': 'virustotal_api_key',
                'type': 'text',
                'label': 'VirusTotal API Key',
                'required': False,
                'default': '',
                'tooltip': 'VirusTotal API key'
            },
            {
                'name': 'censys_api_id',
                'type': 'text',
                'label': 'Censys API ID',
                'required': False,
                'default': '',
                'tooltip': 'Censys API ID'
            },
            {
                'name': 'censys_api_secret',
                'type': 'text',
                'label': 'Censys API Secret',
                'required': False,
                'default': '',
                'tooltip': 'Censys API Secret'
            },
            {
                'name': 'hibp_api_key',
                'type': 'text',
                'label': 'HaveIBeenPwned API Key',
                'required': False,
                'default': '',
                'tooltip': 'Have I Been Pwned API key'
            },
            {
                'name': 'securitytrails_api_key',
                'type': 'text',
                'label': 'SecurityTrails API Key',
                'required': False,
                'default': '',
                'tooltip': 'SecurityTrails API key'
            },
            {
                'name': 'include_subdomains',
                'type': 'checkbox',
                'label': 'Include Subdomain Discovery',
                'required': False,
                'default': True,
                'tooltip': 'Include subdomain discovery in domain analysis'
            },
            {
                'name': 'include_historical',
                'type': 'checkbox',
                'label': 'Include Historical Data',
                'required': False,
                'default': False,
                'tooltip': 'Include historical DNS/certificate data'
            },
            {
                'name': 'max_results',
                'type': 'number',
                'label': 'Max Results per API',
                'required': False,
                'default': 100,
                'min': 10,
                'max': 1000,
                'tooltip': 'Maximum results to retrieve from each API'
            },
            {
                'name': 'concurrent_requests',
                'type': 'number',
                'label': 'Concurrent Requests',
                'required': False,
                'default': 5,
                'min': 1,
                'max': 20,
                'tooltip': 'Number of concurrent API requests'
            },
            {
                'name': 'cache_results',
                'type': 'checkbox',
                'label': 'Cache Results',
                'required': False,
                'default': True,
                'tooltip': 'Cache API results to avoid duplicate requests'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        operation = inputs.get('operation', '')
        if not operation:
            return "Operation is required"
        
        if operation in ['multi_source_lookup', 'shodan_search', 'virustotal_analysis', 'censys_search', 'domain_intelligence', 'ip_intelligence']:
            target = inputs.get('target', '').strip()
            targets_file = inputs.get('targets_file', '').strip()
            search_query = inputs.get('search_query', '').strip()
            
            if not any([target, targets_file, search_query]):
                return "Target, targets file, or search query is required"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API integration operation."""
        try:
            operation = inputs.get('operation', '')
            self.update_progress(f"Starting {operation}...", 0)
            
            # Configure API providers with keys
            self._configure_api_providers(inputs)
            
            # Execute operation
            if operation == 'multi_source_lookup':
                return asyncio.run(self._multi_source_lookup(inputs, config))
            elif operation == 'configure_apis':
                return self._configure_apis(inputs, config)
            elif operation == 'test_connections':
                return asyncio.run(self._test_connections(inputs, config))
            elif operation == 'shodan_search':
                return asyncio.run(self._shodan_search(inputs, config))
            elif operation == 'virustotal_analysis':
                return asyncio.run(self._virustotal_analysis(inputs, config))
            elif operation == 'censys_search':
                return asyncio.run(self._censys_search(inputs, config))
            elif operation == 'breach_check':
                return asyncio.run(self._breach_check(inputs, config))
            elif operation == 'domain_intelligence':
                return asyncio.run(self._domain_intelligence(inputs, config))
            elif operation == 'ip_intelligence':
                return asyncio.run(self._ip_intelligence(inputs, config))
            elif operation == 'bulk_analysis':
                return asyncio.run(self._bulk_analysis(inputs, config))
            elif operation == 'api_status':
                return self._api_status(inputs, config)
            else:
                return {
                    'success': False,
                    'error': f"Unknown operation: {operation}"
                }
        
        except Exception as e:
            self.logger.error(f"Error in API integration: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': operation
            }
    
    def _configure_api_providers(self, inputs: Dict[str, Any]):
        """Configure API providers with provided keys."""
        if inputs.get('shodan_api_key'):
            self.providers['shodan'] = ShodanProvider(inputs['shodan_api_key'])
        
        if inputs.get('virustotal_api_key'):
            self.providers['virustotal'] = VirusTotalProvider(inputs['virustotal_api_key'])
        
        if inputs.get('censys_api_id') and inputs.get('censys_api_secret'):
            self.providers['censys'] = CensysProvider(inputs['censys_api_id'], inputs['censys_api_secret'])
        
        if inputs.get('hibp_api_key'):
            self.providers['haveibeenpwned'] = HaveIBeenPwnedProvider(inputs['hibp_api_key'])
        
        if inputs.get('securitytrails_api_key'):
            self.providers['securitytrails'] = SecurityTrailsProvider(inputs['securitytrails_api_key'])
    
    async def _multi_source_lookup(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform multi-source lookup across multiple APIs."""
        target = inputs.get('target', '').strip()
        if not target:
            return {
                'success': False,
                'error': 'Target is required for multi-source lookup'
            }
        
        self.update_progress("Analyzing target across multiple sources...", 20)
        
        api_providers = inputs.get('api_providers', ['shodan', 'virustotal'])
        results = {
            'target': target,
            'target_type': self._classify_target(target),
            'api_results': {},
            'consolidated_findings': {},
            'risk_assessment': {},
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'apis_used': api_providers
            }
        }
        
        # Determine target type and appropriate APIs
        target_type = results['target_type']
        
        tasks = []
        if 'shodan' in api_providers and target_type in ['ip', 'domain']:
            tasks.append(self._query_shodan_for_target(target, target_type))
        
        if 'virustotal' in api_providers:
            tasks.append(self._query_virustotal_for_target(target, target_type))
        
        if 'censys' in api_providers and target_type in ['ip', 'domain']:
            tasks.append(self._query_censys_for_target(target, target_type))
        
        if 'haveibeenpwned' in api_providers and target_type == 'email':
            tasks.append(self._query_hibp_for_target(target))
        
        if 'securitytrails' in api_providers and target_type == 'domain':
            tasks.append(self._query_securitytrails_for_target(target, inputs))
        
        # Execute queries concurrently
        if tasks:
            self.update_progress("Querying APIs...", 50)
            api_responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process responses
            for i, response in enumerate(api_responses):
                if isinstance(response, Exception):
                    self.logger.error(f"API query failed: {response}")
                    continue
                
                if response and 'provider' in response:
                    results['api_results'][response['provider']] = response['data']
        
        self.update_progress("Consolidating findings...", 80)
        
        # Consolidate findings
        results['consolidated_findings'] = self._consolidate_api_findings(results['api_results'])
        
        # Risk assessment
        results['risk_assessment'] = self._assess_risk_from_apis(results['api_results'])
        
        self.update_progress("Multi-source lookup completed", 100)
        
        return {
            'success': True,
            'operation': 'multi_source_lookup',
            'results': results
        }
    
    async def _query_shodan_for_target(self, target: str, target_type: str) -> Dict[str, Any]:
        """Query Shodan for target information."""
        try:
            provider = self.providers['shodan']
            
            if target_type == 'ip':
                data = await provider.get_host_info(target)
            else:
                # For domains, search for related hosts
                data = await provider.search_hosts(f'hostname:{target}')
            
            return {
                'provider': 'shodan',
                'data': data
            }
        except Exception as e:
            self.logger.error(f"Shodan query failed: {e}")
            return {'provider': 'shodan', 'data': {'error': str(e)}}
    
    async def _query_virustotal_for_target(self, target: str, target_type: str) -> Dict[str, Any]:
        """Query VirusTotal for target information."""
        try:
            provider = self.providers['virustotal']
            
            if target_type == 'ip':
                data = await provider.get_ip_info(target)
            elif target_type == 'domain':
                data = await provider.get_domain_info(target)
            elif target_type == 'url':
                data = await provider.analyze_url(target)
            else:
                data = {'error': f'Unsupported target type for VirusTotal: {target_type}'}
            
            return {
                'provider': 'virustotal',
                'data': data
            }
        except Exception as e:
            self.logger.error(f"VirusTotal query failed: {e}")
            return {'provider': 'virustotal', 'data': {'error': str(e)}}
    
    async def _query_censys_for_target(self, target: str, target_type: str) -> Dict[str, Any]:
        """Query Censys for target information."""
        try:
            provider = self.providers['censys']
            
            if target_type == 'ip':
                data = await provider.get_host_info(target)
            else:
                # For domains, search for related hosts
                data = await provider.search_hosts(f'services.tls.certificates.leaf_data.subject.common_name:{target}')
            
            return {
                'provider': 'censys',
                'data': data
            }
        except Exception as e:
            self.logger.error(f"Censys query failed: {e}")
            return {'provider': 'censys', 'data': {'error': str(e)}}
    
    async def _query_hibp_for_target(self, email: str) -> Dict[str, Any]:
        """Query Have I Been Pwned for email."""
        try:
            provider = self.providers['haveibeenpwned']
            data = await provider.check_email_breaches(email)
            
            return {
                'provider': 'haveibeenpwned',
                'data': data
            }
        except Exception as e:
            self.logger.error(f"HIBP query failed: {e}")
            return {'provider': 'haveibeenpwned', 'data': {'error': str(e)}}
    
    async def _query_securitytrails_for_target(self, domain: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Query SecurityTrails for domain information."""
        try:
            provider = self.providers['securitytrails']
            
            # Get basic domain info
            domain_info = await provider.get_domain_details(domain)
            
            # Get subdomains if requested
            subdomains = None
            if inputs.get('include_subdomains', True):
                subdomains = await provider.get_subdomains(domain)
            
            # Get historical data if requested
            history = None
            if inputs.get('include_historical', False):
                history = await provider.get_domain_history(domain)
            
            data = {
                'domain_info': domain_info,
                'subdomains': subdomains,
                'history': history
            }
            
            return {
                'provider': 'securitytrails',
                'data': data
            }
        except Exception as e:
            self.logger.error(f"SecurityTrails query failed: {e}")
            return {'provider': 'securitytrails', 'data': {'error': str(e)}}
    
    def _classify_target(self, target: str) -> str:
        """Classify the type of target."""
        import re
        
        # IP address pattern
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        # URL pattern
        url_pattern = r'^https?://'
        
        if re.match(url_pattern, target):
            return 'url'
        elif re.match(ip_pattern, target):
            return 'ip'
        elif re.match(email_pattern, target):
            return 'email'
        elif re.match(domain_pattern, target):
            return 'domain'
        else:
            return 'unknown'
    
    def _consolidate_api_findings(self, api_results: Dict[str, Any]) -> Dict[str, Any]:
        """Consolidate findings from multiple APIs."""
        consolidated = {
            'open_ports': set(),
            'services': set(),
            'technologies': set(),
            'certificates': [],
            'vulnerabilities': [],
            'reputation_scores': {},
            'geographic_locations': [],
            'hostnames': set(),
            'subdomains': set()
        }
        
        # Process Shodan results
        if 'shodan' in api_results and api_results['shodan'] and 'error' not in api_results['shodan']:
            shodan_data = api_results['shodan']
            if 'ports' in shodan_data:
                consolidated['open_ports'].update(map(str, shodan_data['ports']))
            if 'data' in shodan_data:
                for service in shodan_data['data']:
                    if 'port' in service:
                        consolidated['open_ports'].add(str(service['port']))
                    if 'product' in service:
                        consolidated['services'].add(service['product'])
        
        # Process VirusTotal results
        if 'virustotal' in api_results and api_results['virustotal'] and 'error' not in api_results['virustotal']:
            vt_data = api_results['virustotal']
            if 'data' in vt_data and 'attributes' in vt_data['data']:
                attrs = vt_data['data']['attributes']
                if 'last_analysis_stats' in attrs:
                    stats = attrs['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    total_count = sum(stats.values())
                    if total_count > 0:
                        consolidated['reputation_scores']['virustotal'] = malicious_count / total_count
        
        # Process SecurityTrails results
        if 'securitytrails' in api_results and api_results['securitytrails'] and 'error' not in api_results['securitytrails']:
            st_data = api_results['securitytrails']
            if 'subdomains' in st_data and st_data['subdomains'] and 'subdomains' in st_data['subdomains']:
                consolidated['subdomains'].update(st_data['subdomains']['subdomains'])
        
        # Convert sets to lists for JSON serialization
        consolidated['open_ports'] = list(consolidated['open_ports'])
        consolidated['services'] = list(consolidated['services'])
        consolidated['technologies'] = list(consolidated['technologies'])
        consolidated['hostnames'] = list(consolidated['hostnames'])
        consolidated['subdomains'] = list(consolidated['subdomains'])
        
        return consolidated
    
    def _assess_risk_from_apis(self, api_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk based on API results."""
        risk_factors = []
        risk_score = 0.0
        
        # Check reputation scores
        for provider, data in api_results.items():
            if provider == 'virustotal' and data and 'data' in data:
                attrs = data['data'].get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                if malicious_count > 0:
                    risk_factors.append(f"Flagged as malicious by {malicious_count} VirusTotal engines")
                    risk_score += min(0.8, malicious_count / 10)
        
        # Check for suspicious services/ports
        consolidated = self._consolidate_api_findings(api_results)
        suspicious_ports = ['22', '23', '1433', '3389', '5900']
        open_suspicious = [p for p in consolidated['open_ports'] if p in suspicious_ports]
        if open_suspicious:
            risk_factors.append(f"Suspicious ports open: {', '.join(open_suspicious)}")
            risk_score += len(open_suspicious) * 0.1
        
        # Normalize risk score
        risk_score = min(1.0, risk_score)
        
        risk_level = 'low'
        if risk_score > 0.7:
            risk_level = 'high'
        elif risk_score > 0.4:
            risk_level = 'medium'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendations': self._generate_risk_recommendations(risk_factors)
        }
    
    def _generate_risk_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []
        
        if any('malicious' in factor.lower() for factor in risk_factors):
            recommendations.append("Block or restrict access to this target due to malicious reputation")
        
        if any('port' in factor.lower() for factor in risk_factors):
            recommendations.append("Review and secure exposed services on suspicious ports")
        
        if not recommendations:
            recommendations.append("Continue monitoring for any suspicious activity")
        
        return recommendations
    
    # Placeholder implementations for other operations
    def _configure_apis(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure API settings."""
        return {
            'success': True,
            'operation': 'configure_apis',
            'message': 'API configuration updated',
            'configured_providers': [name for name, provider in self.providers.items() if provider.enabled]
        }
    
    async def _test_connections(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Test API connections."""
        test_results = {}
        
        for name, provider in self.providers.items():
            if provider.enabled:
                try:
                    # Simple test request
                    if name == 'shodan':
                        result = await provider.make_request('/api-info', params={'key': provider.api_key})
                    elif name == 'virustotal':
                        result = await provider.make_request('/users/self')
                    else:
                        result = {'status': 'unknown'}
                    
                    test_results[name] = {
                        'status': 'success' if result and 'error' not in result else 'failed',
                        'details': result
                    }
                except Exception as e:
                    test_results[name] = {
                        'status': 'failed',
                        'error': str(e)
                    }
            else:
                test_results[name] = {
                    'status': 'disabled',
                    'reason': 'No API key provided'
                }
        
        return {
            'success': True,
            'operation': 'test_connections',
            'test_results': test_results
        }
    
    async def _shodan_search(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Shodan search."""
        query = inputs.get('search_query', inputs.get('target', ''))
        if not query:
            return {'success': False, 'error': 'Search query is required'}
        
        provider = self.providers['shodan']
        if not provider.enabled:
            return {'success': False, 'error': 'Shodan API key not configured'}
        
        max_results = inputs.get('max_results', 100)
        results = await provider.search_hosts(query, max_results)
        
        return {
            'success': True,
            'operation': 'shodan_search',
            'query': query,
            'results': results
        }
    
    async def _virustotal_analysis(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform VirusTotal analysis."""
        target = inputs.get('target', '')
        if not target:
            return {'success': False, 'error': 'Target is required'}
        
        provider = self.providers['virustotal']
        if not provider.enabled:
            return {'success': False, 'error': 'VirusTotal API key not configured'}
        
        target_type = self._classify_target(target)
        
        if target_type == 'url':
            results = await provider.analyze_url(target)
        elif target_type == 'domain':
            results = await provider.get_domain_info(target)
        elif target_type == 'ip':
            results = await provider.get_ip_info(target)
        else:
            return {'success': False, 'error': f'Unsupported target type: {target_type}'}
        
        return {
            'success': True,
            'operation': 'virustotal_analysis',
            'target': target,
            'target_type': target_type,
            'results': results
        }
    
    async def _censys_search(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Censys search."""
        query = inputs.get('search_query', inputs.get('target', ''))
        if not query:
            return {'success': False, 'error': 'Search query is required'}
        
        provider = self.providers['censys']
        if not provider.enabled:
            return {'success': False, 'error': 'Censys API credentials not configured'}
        
        max_results = inputs.get('max_results', 100)
        results = await provider.search_hosts(query, max_results)
        
        return {
            'success': True,
            'operation': 'censys_search',
            'query': query,
            'results': results
        }
    
    async def _breach_check(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check for data breaches."""
        target = inputs.get('target', '')
        if not target or self._classify_target(target) != 'email':
            return {'success': False, 'error': 'Valid email address is required'}
        
        provider = self.providers['haveibeenpwned']
        if not provider.enabled:
            return {'success': False, 'error': 'Have I Been Pwned API key not configured'}
        
        results = await provider.check_email_breaches(target)
        
        return {
            'success': True,
            'operation': 'breach_check',
            'email': target,
            'results': results
        }
    
    async def _domain_intelligence(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive domain intelligence."""
        domain = inputs.get('target', '')
        if not domain or self._classify_target(domain) != 'domain':
            return {'success': False, 'error': 'Valid domain is required'}
        
        # Multi-API domain analysis
        return await self._multi_source_lookup(inputs, config)
    
    async def _ip_intelligence(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive IP intelligence."""
        ip = inputs.get('target', '')
        if not ip or self._classify_target(ip) != 'ip':
            return {'success': False, 'error': 'Valid IP address is required'}
        
        # Multi-API IP analysis
        return await self._multi_source_lookup(inputs, config)
    
    async def _bulk_analysis(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Bulk analysis of multiple targets."""
        targets_file = inputs.get('targets_file', '')
        if not targets_file:
            return {'success': False, 'error': 'Targets file is required'}
        
        try:
            with open(targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {'success': False, 'error': f'Error reading targets file: {e}'}
        
        if not targets:
            return {'success': False, 'error': 'No targets found in file'}
        
        results = {}
        total_targets = len(targets)
        
        for i, target in enumerate(targets):
            if not self.should_continue():
                break
            
            progress = (i / total_targets) * 100
            self.update_progress(f"Analyzing target {i+1}/{total_targets}: {target}", int(progress))
            
            # Create a modified inputs dict for this target
            target_inputs = inputs.copy()
            target_inputs['target'] = target
            
            target_result = await self._multi_source_lookup(target_inputs, config)
            results[target] = target_result
            
            # Small delay to avoid overwhelming APIs
            await asyncio.sleep(0.5)
        
        return {
            'success': True,
            'operation': 'bulk_analysis',
            'total_targets': total_targets,
            'analyzed_targets': len(results),
            'results': results
        }
    
    def _api_status(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get API status and configuration."""
        status = {}
        
        for name, provider in self.providers.items():
            status[name] = {
                'enabled': provider.enabled,
                'base_url': provider.base_url,
                'rate_limit': provider.rate_limit,
                'has_api_key': bool(provider.api_key),
                'last_request_time': provider.last_request_time,
                'request_count': provider.request_count
            }
        
        return {
            'success': True,
            'operation': 'api_status',
            'providers_status': status,
            'total_providers': len(self.providers),
            'enabled_providers': len([p for p in self.providers.values() if p.enabled])
        }
