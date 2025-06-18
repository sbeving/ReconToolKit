"""
Web Fuzzer Module
Performs web fuzzing to discover hidden parameters and vulnerabilities.
"""

import logging
import time
import os
import asyncio
import aiohttp
import re
import urllib.parse
import random
import string
from typing import Dict, Any, List, Optional
from modules.base_module import BaseModule


class WebFuzzerModule(BaseModule):
    """Web fuzzing module for parameter discovery and testing."""
    
    def __init__(self):
        super().__init__(
            name="Web Fuzzer",
            description="Discover hidden parameters and potential web vulnerabilities through fuzzing",
            category="active"
        )
        
        self.logger = logging.getLogger(__name__)
        self._stop_requested = False
        self._processed_count = 0
        self._total_count = 0
        self._start_time = 0
        self._found_params = []
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """
        Get list of input fields required for this module.
        
        Returns:
            List[Dict[str, Any]]: List of input field definitions
        """
        return [
            {
                'name': 'target_url',
                'type': 'text',
                'label': 'Target URL',
                'required': True,
                'default': '',
                'placeholder': 'https://example.com/page.php'
            },
            {
                'name': 'method',
                'type': 'select',
                'label': 'HTTP Method',
                'required': True,
                'default': 'GET',
                'options': [
                    ('GET', 'GET'),
                    ('POST', 'POST'),
                ]
            },
            {
                'name': 'wordlist',
                'type': 'file',
                'label': 'Parameters Wordlist',
                'required': False,
                'default': '',
                'placeholder': 'Select a wordlist file or use default'
            },
            {
                'name': 'test_types',
                'type': 'multiselect',
                'label': 'Parameter Test Types',
                'required': True,
                'default': ['discovery'],
                'options': [
                    ('Parameter Discovery', 'discovery'),
                    ('XSS Reflection Check', 'xss'),
                    ('SQL Injection Check', 'sqli'),
                    ('LFI Check', 'lfi')
                ]
            },
            {
                'name': 'threads',
                'type': 'number',
                'label': 'Concurrent Requests',
                'required': False,
                'default': 20,
                'min': 1,
                'max': 50
            },
            {
                'name': 'follow_redirects',
                'type': 'checkbox',
                'label': 'Follow Redirects',
                'required': False,
                'default': True
            },
            {
                'name': 'timeout',
                'type': 'number',
                'label': 'Timeout (seconds)',
                'required': False,
                'default': 10,
                'min': 1,
                'max': 30
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
        target_url = inputs.get('target_url', '')
        
        if not target_url:
            return "Target URL is required"
        
        try:
            parsed = urllib.parse.urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return "Invalid URL format. Must include scheme (http:// or https://) and domain"
        except Exception:
            return "Invalid URL format"
        
        threads = inputs.get('threads', 20)
        try:
            threads_int = int(threads)
            if threads_int < 1 or threads_int > 50:
                return "Threads must be between 1 and 50"
        except ValueError:
            return "Threads must be a number"
        
        test_types = inputs.get('test_types', [])
        if not test_types:
            return "At least one test type must be selected"
            
        wordlist_path = inputs.get('wordlist', '')
        if wordlist_path and not os.path.isfile(wordlist_path):
            return f"Wordlist file does not exist: {wordlist_path}"
        
        return None
    
    def get_default_param_wordlist(self) -> List[str]:
        """Get the default parameter wordlist."""
        return [
            # Common parameters
            "id", "page", "file", "dir", "search", "query", "lang", "view",
            "action", "type", "name", "key", "value", "data", "path", "url",
            "category", "cat", "p", "q", "s", "src", "dest", "destination",
            "redirect", "redir", "return", "auth", "token", "access", "user",
            "username", "user_id", "userid", "email", "password", "pass", "pwd",
            "order", "sort", "filter", "limit", "offset", "debug", "mode",
            "content", "template", "theme", "style", "format", "callback",
            "cmd", "exec", "command", "execute", "system", "code", "status",
            "msg", "message", "error", "warn", "debug_level", "log", "config",
            "option", "settings", "set", "param", "parameter", "function", "f",
            "func", "do", "task", "process", "run", "go", "show", "display",
            "site", "website", "host", "domain", "port", "ssl", "api", "api_key",
            "apikey", "method", "version", "ver", "ref", "reference", "link",
            "height", "width", "size", "length", "level", "time", "date",
            "year", "month", "day", "hour", "minute", "second", "timestamp",
            "locale", "location", "loc", "coordinates", "lat", "latitude",
            "long", "longitude", "position", "device", "mobile", "desktop",
            "browser", "client", "app", "application", "agent", "ip", "address",
            "remote", "proxy", "title", "subject", "body", "content_type",
            "nonce", "hash", "md5", "sha1", "sha256", "crypt", "crc", "sess",
            "session", "cookie", "csrf", "xsrf", "state", "price", "cost",
            "amount", "total", "sum", "item", "product", "prod", "service",
            "account", "group", "role", "permission", "rights", "admin"
        ]
    
    def get_payloads_for_test_type(self, param_name: str, test_type: str) -> List[Dict[str, str]]:
        """
        Get payloads for the specified test type.
        
        Args:
            param_name: The parameter name to test
            test_type: Type of test ('discovery', 'xss', 'sqli', 'lfi')
            
        Returns:
            List of payload dictionaries with name, value, and description
        """
        payloads = []
        
        if test_type == 'discovery':
            # Just test with a random value to see if the parameter is processed
            random_value = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            payloads.append({
                'name': param_name,
                'value': random_value,
                'description': 'Parameter discovery'
            })
            
        elif test_type == 'xss':
            # Simple XSS test payloads
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"onmouseover="alert(1)',
                'javascript:alert(1)'
            ]
            for payload in xss_payloads:
                payloads.append({
                    'name': param_name,
                    'value': payload,
                    'description': 'XSS test'
                })
                
        elif test_type == 'sqli':
            # Simple SQL Injection test payloads
            sqli_payloads = [
                "'", 
                '"', 
                "' OR '1'='1", 
                '" OR "1"="1',
                "' OR '1'='1' --",
                "1' OR '1'='1",
                "1 OR 1=1",
                "' UNION SELECT 1,2,3 --",
                "1'; WAITFOR DELAY '0:0:5' --"
            ]
            for payload in sqli_payloads:
                payloads.append({
                    'name': param_name,
                    'value': payload,
                    'description': 'SQLi test'
                })
                
        elif test_type == 'lfi':
            # Local File Inclusion test payloads
            lfi_payloads = [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\Windows\\win.ini",
                "file:///etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php"
            ]
            for payload in lfi_payloads:
                payloads.append({
                    'name': param_name,
                    'value': payload,
                    'description': 'LFI test'
                })
        
        return payloads
    
    def get_success_patterns(self, test_type: str) -> Dict[str, Any]:
        """Get patterns that might indicate successful exploitation."""
        patterns = {
            'xss': {
                'content': [re.compile(r'<script>alert\(1\)</script>'),
                           re.compile(r'<img src=x onerror=alert\(1\)>')]
            },
            'sqli': {
                'content': [re.compile(r'SQL syntax|mysql_fetch|ORA-[0-9]|Oracle|Microsoft SQL Server|PostgreSQL')],
                'error_msgs': ['SQL syntax', 'mysql_fetch', 'ORA-', 'Oracle Error', 'SQL Server', 'PostgreSQL']
            },
            'lfi': {
                'content': [re.compile(r'root:x:|Administrator:|boot loader|\\[boot\\]|\\[fonts\\]')],
                'specific_files': ['root:', 'bin:', 'daemon:', 'mail:', '[boot]', '[fonts]']
            }
        }
        return patterns.get(test_type, {})
    
    def analyze_response(self, response_data: Dict[str, Any], payload: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze the response to determine if the payload had an effect.
        
        Args:
            response_data: Response data from the request
            payload: The payload that was used
            
        Returns:
            Dictionary with analysis results
        """
        test_type = payload.get('description', '').split()[0].lower()
        param_name = payload.get('name', '')
        param_value = payload.get('value', '')
        content = response_data.get('response_text', '')
        status_code = response_data.get('status_code', 0)
        content_type = response_data.get('content_type', '')
        
        result = {
            'param_name': param_name,
            'payload': param_value,
            'test_type': test_type,
            'status_code': status_code,
            'content_length': len(content),
            'content_type': content_type,
            'interesting': False,
            'reason': []
        }
        
        # Basic analysis - look for the parameter value in the response
        if param_value in content and len(param_value) > 5:
            result['interesting'] = True
            result['reason'].append(f"Parameter value reflected in response")
        
        # Test type specific analysis
        if test_type == 'discovery':
            # For discovery, we're mostly interested in different behavior
            if status_code in [200, 301, 302]:
                result['interesting'] = True
                result['reason'].append(f"Parameter accepted (status {status_code})")
                
        elif test_type in ['xss', 'sqli', 'lfi']:
            # Look for specific patterns based on test type
            patterns = self.get_success_patterns(test_type)
            
            # Check content patterns
            if 'content' in patterns:
                for pattern in patterns['content']:
                    if pattern.search(content):
                        result['interesting'] = True
                        result['reason'].append(f"Found pattern indicating {test_type} vulnerability")
                        break
            
            # Check for error messages
            if 'error_msgs' in patterns:
                for error_msg in patterns['error_msgs']:
                    if error_msg.lower() in content.lower():
                        result['interesting'] = True
                        result['reason'].append(f"Error message suggests {test_type} vulnerability")
                        break
            
            # Check for specific file contents (LFI)
            if test_type == 'lfi' and 'specific_files' in patterns:
                for file_indicator in patterns['specific_files']:
                    if file_indicator in content:
                        result['interesting'] = True
                        result['reason'].append(f"Response contains {test_type} file indicators")
                        break
        
        return result
    
    async def fetch_with_payload(self, session, url: str, method: str, payload: Dict[str, str], 
                               follow_redirects: bool = True, timeout: int = 10) -> Dict[str, Any]:
        """
        Make a request with the given payload.
        
        Args:
            session: aiohttp Client Session
            url: Base URL
            method: HTTP method (GET or POST)
            payload: Parameter payload
            follow_redirects: Whether to follow redirects
            timeout: Request timeout in seconds
            
        Returns:
            Response data
        """
        if self._stop_requested:
            return None
            
        param_name = payload['name']
        param_value = payload['value']
        
        # Append parameter to URL for GET or prepare data for POST
        if method == 'GET':
            # Parse the URL to handle existing parameters
            parsed_url = urllib.parse.urlparse(url)
            query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
            
            # Add our parameter
            query_dict[param_name] = param_value
            
            # Build the new URL
            new_query = urllib.parse.urlencode(query_dict)
            new_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            post_data = None
        else:  # POST
            new_url = url
            post_data = {param_name: param_value}
        
        try:
            start_time = time.time()
            
            if method == 'GET':
                async with session.get(
                    new_url, 
                    allow_redirects=follow_redirects,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    elapsed = time.time() - start_time
                    response_text = await response.text(errors='replace')
                    
                    return {
                        'url': new_url,
                        'method': method,
                        'status_code': response.status,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response_text),
                        'elapsed': elapsed,
                        'response_text': response_text,
                        'redirect_url': str(response.url) if str(response.url) != new_url else None,
                        'param_name': param_name,
                        'param_value': param_value,
                        'headers': dict(response.headers)
                    }
            else:  # POST
                async with session.post(
                    new_url, 
                    data=post_data,
                    allow_redirects=follow_redirects,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    elapsed = time.time() - start_time
                    response_text = await response.text(errors='replace')
                    
                    return {
                        'url': new_url,
                        'method': method,
                        'status_code': response.status,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response_text),
                        'elapsed': elapsed,
                        'response_text': response_text,
                        'redirect_url': str(response.url) if str(response.url) != new_url else None,
                        'param_name': param_name,
                        'param_value': param_value,
                        'headers': dict(response.headers)
                    }
                    
        except Exception as e:
            return {
                'url': new_url,
                'method': method,
                'status_code': 0,
                'content_type': '',
                'content_length': 0,
                'elapsed': time.time() - start_time,
                'error': str(e),
                'param_name': param_name,
                'param_value': param_value
            }
        finally:
            self._processed_count += 1
            progress = int((self._processed_count / self._total_count) * 100)
            elapsed_total = time.time() - self._start_time
            remaining = (elapsed_total / self._processed_count) * (self._total_count - self._processed_count) if self._processed_count > 0 else 0
            self.update_progress(
                f"Testing: {self._processed_count}/{self._total_count} requests "
                f"({progress}%) - {len(self._found_params)} issues found "
                f"[ETA: {int(remaining/60)}m {int(remaining%60)}s]",
                progress
            )
    
    async def process_batch(self, session, url: str, method: str, payloads: List[Dict[str, str]],
                          follow_redirects: bool, timeout: int) -> List[Dict[str, Any]]:
        """Process a batch of payloads concurrently."""
        if self._stop_requested:
            return []
            
        tasks = [self.fetch_with_payload(session, url, method, payload, follow_redirects, timeout) 
                for payload in payloads]
        responses = await asyncio.gather(*tasks)
        
        # Analyze responses
        results = []
        for response, payload in zip(responses, payloads):
            if response:
                analysis = self.analyze_response(response, payload)
                if analysis['interesting']:
                    self._found_params.append(analysis)
                    results.append({**response, **analysis})
        
        return results
    
    async def fuzz_parameters(self, url: str, method: str, params: List[str], test_types: List[str],
                            batch_size: int, follow_redirects: bool, timeout: int) -> List[Dict[str, Any]]:
        """
        Fuzz parameters by testing them with various payloads.
        
        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            params: List of parameter names to test
            test_types: Types of tests to perform
            batch_size: Number of concurrent requests
            follow_redirects: Whether to follow redirects
            timeout: Request timeout in seconds
            
        Returns:
            List of interesting findings
        """
        # Generate all payloads for testing
        all_payloads = []
        for param in params:
            for test_type in test_types:
                all_payloads.extend(self.get_payloads_for_test_type(param, test_type))
                
        self._total_count = len(all_payloads)
        self._processed_count = 0
        self._start_time = time.time()
        self._found_params = []
        
        self.logger.info(f"Starting web fuzzing on {url} with {self._total_count} payloads")
        
        # Initialize results
        findings = []
        
        # Create session with appropriate headers
        async with aiohttp.ClientSession(
            headers={
                'User-Agent': self.get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache'
            },
            timeout=aiohttp.ClientTimeout(total=timeout + 5)
        ) as session:
            # First, make a baseline request to compare against
            try:
                if method == 'GET':
                    base_response = await session.get(url, allow_redirects=follow_redirects, ssl=False)
                else:
                    base_response = await session.post(url, allow_redirects=follow_redirects, ssl=False)
                    
                base_status = base_response.status
                base_content = await base_response.text(errors='replace')
                base_content_length = len(base_content)
                
                self.logger.debug(f"Baseline response: status={base_status}, length={base_content_length}")
            except Exception as e:
                self.logger.error(f"Error getting baseline response: {e}")
                base_status = 0
                base_content = ""
                base_content_length = 0
            
            # Process payloads in batches
            for i in range(0, len(all_payloads), batch_size):
                if self._stop_requested:
                    break
                    
                batch = all_payloads[i:i+batch_size]
                batch_results = await self.process_batch(
                    session, url, method, batch, follow_redirects, timeout
                )
                
                findings.extend(batch_results)
        
        return findings
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run web fuzzing scan.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            config (Dict[str, Any]): Configuration parameters
            
        Returns:
            Dict[str, Any]: Scan results
        """
        self._stop_requested = False
        
        target_url = inputs.get('target_url', '')
        method = inputs.get('method', 'GET')
        wordlist_path = inputs.get('wordlist', '')
        test_types = inputs.get('test_types', ['discovery'])
        follow_redirects = inputs.get('follow_redirects', True)
        threads = int(inputs.get('threads', 20))
        timeout = int(inputs.get('timeout', 10))
        
        # Load parameter wordlist
        params = []
        if wordlist_path and os.path.isfile(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    params = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                self.logger.error(f"Error reading wordlist file: {e}")
                params = self.get_default_param_wordlist()
        else:
            params = self.get_default_param_wordlist()
        
        self.logger.info(f"Using parameter list with {len(params)} entries")
        self.update_progress(f"Starting web fuzzing on {target_url} with {len(params)} parameters", 0)
        
        try:
            # Create event loop and run the async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            start_time = time.time()
            findings = loop.run_until_complete(self.fuzz_parameters(
                target_url, method, params, test_types, threads, follow_redirects, timeout
            ))
            scan_time = time.time() - start_time
            loop.close()
            
            # Process and format results by grouping similar findings
            results = {
                'scan_info': {
                    'target_url': target_url,
                    'method': method,
                    'total_tests': self._total_count,
                    'scan_time': f"{scan_time:.2f} seconds",
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'wordlist': wordlist_path or "Default parameter list",
                    'wordlist_size': len(params),
                    'test_types': test_types,
                    'threads': threads,
                    'follow_redirects': follow_redirects,
                    'timeout': timeout
                },
                'results': {
                    'total_findings': len(findings),
                    'findings_by_param': {}
                }
            }
            
            # Group findings by parameter
            param_findings = {}
            for finding in findings:
                param_name = finding.get('param_name', '')
                if param_name not in param_findings:
                    param_findings[param_name] = []
                param_findings[param_name].append(finding)
            
            # Add to results
            results['results']['findings_by_param'] = param_findings
            
            # Add summary for quick reference
            vulnerability_count = {}
            for finding in findings:
                test_type = finding.get('test_type', '')
                if test_type not in vulnerability_count:
                    vulnerability_count[test_type] = 0
                vulnerability_count[test_type] += 1
                
            results['summary'] = {
                'target_url': target_url,
                'method': method,
                'total_tests': self._total_count,
                'total_findings': len(findings),
                'parameters_tested': len(params),
                'vulnerable_parameters': len(param_findings),
                'vulnerabilities_by_type': vulnerability_count,
                'scan_duration': f"{scan_time:.2f} seconds"
            }
            
            self.update_progress(
                f"Scan completed: Found {len(findings)} potential issues in {len(param_findings)} parameters on {target_url}", 
                100
            )
            return results
            
        except Exception as e:
            self.logger.error(f"Web fuzzing error: {str(e)}")
            raise Exception(f"Web fuzzing error: {str(e)}")
    
    def stop_scan(self):
        """Stop the current scan operation."""
        self._stop_requested = True
        super().stop_scan()
