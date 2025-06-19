"""
Advanced Web Crawler Module
Comprehensive web crawling and site mapping with JavaScript rendering.
"""

import logging
import asyncio
import aiohttp
import time
import re
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
from collections import defaultdict, deque
import json
from modules.base_module import BaseModule


class CrawlResult:
    """Represents a crawled page result."""
    
    def __init__(self, url: str, status_code: int, content: str = "", headers: Dict[str, str] = None):
        self.url = url
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
        self.timestamp = datetime.now().isoformat()
        self.content_type = headers.get('Content-Type', '') if headers else ''
        self.content_length = len(content)
        self.response_time = 0.0
        
        # Extracted data
        self.links = set()
        self.forms = []
        self.inputs = []
        self.comments = []
        self.scripts = []
        self.styles = []
        self.images = []
        self.endpoints = []
        self.parameters = set()
        self.technologies = set()
        self.security_headers = {}
        self.cookies = {}
        
    def extract_data(self):
        """Extract various data from the page content."""
        if not self.content:
            return
        
        # Extract links
        link_pattern = re.compile(r'<a[^>]*href\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        self.links.update(link_pattern.findall(self.content))
        
        # Extract forms
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        forms = form_pattern.findall(self.content)
        for form in forms:
            # Extract action and method
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
            method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
            
            form_data = {
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': []
            }
            
            # Extract input fields
            input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
            inputs = input_pattern.findall(form)
            for input_tag in inputs:
                name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                
                if name_match:
                    form_data['inputs'].append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text'
                    })
            
            self.forms.append(form_data)
        
        # Extract script sources
        script_pattern = re.compile(r'<script[^>]*src\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        self.scripts.extend(script_pattern.findall(self.content))
        
        # Extract stylesheets
        style_pattern = re.compile(r'<link[^>]*href\s*=\s*["\']([^"\']*)["\'][^>]*rel\s*=\s*["\']stylesheet["\'][^>]*>', re.IGNORECASE)
        self.styles.extend(style_pattern.findall(self.content))
        
        # Extract images
        img_pattern = re.compile(r'<img[^>]*src\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        self.images.extend(img_pattern.findall(self.content))
        
        # Extract comments
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        self.comments.extend(comment_pattern.findall(self.content))
        
        # Extract parameters from URL
        parsed_url = urlparse(self.url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            self.parameters.update(params.keys())
        
        # Detect technologies
        self._detect_technologies()
        
        # Extract security headers
        self.security_headers = self._extract_security_headers()
    
    def _detect_technologies(self):
        """Detect web technologies from content and headers."""
        content_lower = self.content.lower()
        
        # Framework detection
        if 'laravel' in content_lower or 'laravel_session' in content_lower:
            self.technologies.add('Laravel')
        if 'django' in content_lower or 'csrfmiddlewaretoken' in content_lower:
            self.technologies.add('Django')
        if 'rails' in content_lower or 'authenticity_token' in content_lower:
            self.technologies.add('Ruby on Rails')
        if 'asp.net' in content_lower or 'viewstate' in content_lower:
            self.technologies.add('ASP.NET')
        if 'wordpress' in content_lower or 'wp-content' in content_lower:
            self.technologies.add('WordPress')
        if 'drupal' in content_lower or 'drupal-' in content_lower:
            self.technologies.add('Drupal')
        if 'joomla' in content_lower:
            self.technologies.add('Joomla')
        
        # JavaScript frameworks
        if 'react' in content_lower or '_react' in content_lower:
            self.technologies.add('React')
        if 'angular' in content_lower or 'ng-' in content_lower:
            self.technologies.add('Angular')
        if 'vue' in content_lower or 'v-' in content_lower:
            self.technologies.add('Vue.js')
        if 'jquery' in content_lower:
            self.technologies.add('jQuery')
        
        # Server detection from headers
        server_header = self.headers.get('Server', '')
        if server_header:
            if 'apache' in server_header.lower():
                self.technologies.add('Apache')
            elif 'nginx' in server_header.lower():
                self.technologies.add('Nginx')
            elif 'iis' in server_header.lower():
                self.technologies.add('IIS')
    
    def _extract_security_headers(self) -> Dict[str, str]:
        """Extract security-related headers."""
        security_headers = {}
        
        security_header_names = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Strict-Transport-Security', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy'
        ]
        
        for header_name in security_header_names:
            if header_name in self.headers:
                security_headers[header_name] = self.headers[header_name]
        
        return security_headers


class AdvancedWebCrawlerModule(BaseModule):
    """Advanced web crawler with comprehensive site mapping and analysis."""
    
    def __init__(self):
        super().__init__(
            name="Advanced Web Crawler",
            description="Comprehensive web crawling and site mapping with JavaScript rendering and security analysis",
            category="active"
        )
        
        self.logger = logging.getLogger(__name__)
        self.crawled_urls = set()
        self.url_queue = deque()
        self.results = {}
        self.robots_txt = {}
        self.sitemap_urls = set()
        self.error_pages = []
        self.redirect_chains = []
        
        # Crawl statistics
        self.stats = {
            'total_urls_found': 0,
            'total_urls_crawled': 0,
            'total_forms_found': 0,
            'total_parameters_found': 0,
            'total_errors': 0,
            'average_response_time': 0.0,
            'technologies_detected': set(),
            'security_issues': []
        }
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'target_url',
                'type': 'text',
                'label': 'Target URL',
                'required': True,
                'default': '',
                'placeholder': 'https://example.com'
            },
            {
                'name': 'crawl_depth',
                'type': 'number',
                'label': 'Crawl Depth',
                'required': False,
                'default': 3,
                'min': 1,
                'max': 10,
                'tooltip': 'Maximum depth to crawl from the starting URL'
            },
            {
                'name': 'max_pages',
                'type': 'number',
                'label': 'Max Pages',
                'required': False,
                'default': 100,
                'min': 1,
                'max': 1000,
                'tooltip': 'Maximum number of pages to crawl'
            },
            {
                'name': 'crawl_mode',
                'type': 'combo',
                'label': 'Crawl Mode',
                'required': False,
                'default': 'comprehensive',
                'options': ['fast', 'comprehensive', 'stealth', 'aggressive'],
                'tooltip': 'Crawling strategy and intensity'
            },
            {
                'name': 'respect_robots',
                'type': 'checkbox',
                'label': 'Respect robots.txt',
                'required': False,
                'default': True,
                'tooltip': 'Follow robots.txt directives'
            },
            {
                'name': 'follow_redirects',
                'type': 'checkbox',
                'label': 'Follow Redirects',
                'required': False,
                'default': True
            },
            {
                'name': 'crawl_external_links',
                'type': 'checkbox',
                'label': 'Crawl External Links',
                'required': False,
                'default': False,
                'tooltip': 'Follow links to external domains'
            },
            {
                'name': 'analyze_forms',
                'type': 'checkbox',
                'label': 'Analyze Forms',
                'required': False,
                'default': True,
                'tooltip': 'Extract and analyze HTML forms'
            },
            {
                'name': 'extract_parameters',
                'type': 'checkbox',
                'label': 'Extract Parameters',
                'required': False,
                'default': True,
                'tooltip': 'Extract URL parameters and form inputs'
            },
            {
                'name': 'detect_technologies',
                'type': 'checkbox',
                'label': 'Detect Technologies',
                'required': False,
                'default': True,
                'tooltip': 'Identify web technologies and frameworks'
            },
            {
                'name': 'check_security_headers',
                'type': 'checkbox',
                'label': 'Check Security Headers',
                'required': False,
                'default': True,
                'tooltip': 'Analyze security-related HTTP headers'
            },
            {
                'name': 'crawl_sitemap',
                'type': 'checkbox',
                'label': 'Crawl Sitemap',
                'required': False,
                'default': True,
                'tooltip': 'Parse and crawl URLs from sitemap.xml'
            },
            {
                'name': 'screenshot_pages',
                'type': 'checkbox',
                'label': 'Take Screenshots',
                'required': False,
                'default': False,
                'tooltip': 'Take screenshots of pages (requires browser)'
            },
            {
                'name': 'concurrent_requests',
                'type': 'number',
                'label': 'Concurrent Requests',
                'required': False,
                'default': 10,
                'min': 1,
                'max': 50,
                'tooltip': 'Number of concurrent HTTP requests'
            },
            {
                'name': 'request_delay',
                'type': 'number',
                'label': 'Request Delay (seconds)',
                'required': False,
                'default': 1,
                'min': 0,
                'max': 10,
                'tooltip': 'Delay between requests to avoid overloading server'
            },
            {
                'name': 'user_agent',
                'type': 'text',
                'label': 'User Agent',
                'required': False,
                'default': 'ReconToolKit-Crawler/1.0.0',
                'placeholder': 'Custom User-Agent string'
            },
            {
                'name': 'custom_headers',
                'type': 'text',
                'label': 'Custom Headers',
                'required': False,
                'default': '',
                'placeholder': 'Header1: Value1\\nHeader2: Value2',
                'tooltip': 'Custom HTTP headers (one per line)'
            },
            {
                'name': 'timeout',
                'type': 'number',
                'label': 'Request Timeout (seconds)',
                'required': False,
                'default': 15,
                'min': 5,
                'max': 60
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        target_url = inputs.get('target_url', '').strip()
        if not target_url:
            return "Target URL is required"
        
        if not target_url.startswith(('http://', 'https://')):
            return "Target URL must start with http:// or https://"
        
        crawl_depth = inputs.get('crawl_depth', 3)
        if crawl_depth < 1 or crawl_depth > 10:
            return "Crawl depth must be between 1 and 10"
        
        max_pages = inputs.get('max_pages', 100)
        if max_pages < 1 or max_pages > 1000:
            return "Max pages must be between 1 and 1000"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run the web crawling operation."""
        try:
            self.update_progress("Initializing web crawler...", 0)
            
            target_url = inputs.get('target_url', '').strip()
            crawl_depth = inputs.get('crawl_depth', 3)
            max_pages = inputs.get('max_pages', 100)
            crawl_mode = inputs.get('crawl_mode', 'comprehensive')
            
            # Reset crawler state
            self.crawled_urls.clear()
            self.url_queue.clear()
            self.results.clear()
            self.stats = {
                'total_urls_found': 0,
                'total_urls_crawled': 0,
                'total_forms_found': 0,
                'total_parameters_found': 0,
                'total_errors': 0,
                'average_response_time': 0.0,
                'technologies_detected': set(),
                'security_issues': []
            }
            
            # Parse base URL
            parsed_url = urlparse(target_url)
            base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Start crawling
            self.update_progress("Starting web crawl...", 10)
            results = asyncio.run(self._run_crawl(inputs, config))
            
            # Generate comprehensive results
            final_results = {
                'success': True,
                'target_url': target_url,
                'base_domain': base_domain,
                'crawl_config': {
                    'depth': crawl_depth,
                    'max_pages': max_pages,
                    'mode': crawl_mode,
                    'respect_robots': inputs.get('respect_robots', True),
                    'external_links': inputs.get('crawl_external_links', False)
                },
                'crawl_results': results,
                'statistics': self._generate_statistics(),
                'site_map': self._generate_site_map(),
                'forms_analysis': self._analyze_forms(),
                'parameters_analysis': self._analyze_parameters(),
                'technologies_detected': list(self.stats['technologies_detected']),
                'security_analysis': self._analyze_security(),
                'recommendations': self._generate_recommendations(),
                'metadata': {
                    'crawl_start_time': datetime.now().isoformat(),
                    'total_pages_crawled': len(self.crawled_urls),
                    'unique_domains': len(set(urlparse(url).netloc for url in self.crawled_urls))
                }
            }
            
            self.update_progress("Web crawling completed", 100)
            return final_results
            
        except Exception as e:
            self.logger.error(f"Error in web crawler: {e}")
            return {
                'success': False,
                'error': str(e),
                'target_url': inputs.get('target_url', '')
            }
    
    async def _run_crawl(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run the actual crawling process."""
        target_url = inputs.get('target_url')
        crawl_depth = inputs.get('crawl_depth', 3)
        max_pages = inputs.get('max_pages', 100)
        concurrent_requests = inputs.get('concurrent_requests', 10)
        request_delay = inputs.get('request_delay', 1)
        timeout = inputs.get('timeout', 15)
        user_agent = inputs.get('user_agent', 'ReconToolKit-Crawler/1.0.0')
        
        # Parse custom headers
        custom_headers = {}
        if inputs.get('custom_headers'):
            for line in inputs['custom_headers'].split('\\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    custom_headers[key.strip()] = value.strip()
        
        # Initialize URL queue
        self.url_queue.append((target_url, 0))  # (url, depth)
        
        # Check robots.txt if required
        if inputs.get('respect_robots', True):
            await self._fetch_robots_txt(target_url)
        
        # Check sitemap if required
        if inputs.get('crawl_sitemap', True):
            await self._fetch_sitemap(target_url)
        
        # Create HTTP session
        connector = aiohttp.TCPConnector(limit=concurrent_requests)
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        headers.update(custom_headers)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers=headers
        ) as session:
            
            # Main crawling loop
            semaphore = asyncio.Semaphore(concurrent_requests)
            
            while self.url_queue and len(self.crawled_urls) < max_pages:
                if not self.should_continue():
                    break
                
                # Get batch of URLs to process
                batch = []
                batch_size = min(concurrent_requests, len(self.url_queue), max_pages - len(self.crawled_urls))
                
                for _ in range(batch_size):
                    if self.url_queue:
                        batch.append(self.url_queue.popleft())
                
                if not batch:
                    break
                
                # Process batch concurrently
                tasks = []
                for url, depth in batch:
                    if url not in self.crawled_urls and depth <= crawl_depth:
                        task = self._crawl_url(session, semaphore, url, depth, inputs)
                        tasks.append(task)
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                # Delay between batches
                if request_delay > 0:
                    await asyncio.sleep(request_delay)
                
                # Update progress
                progress = min(90, (len(self.crawled_urls) / max_pages) * 80 + 10)
                self.update_progress(f"Crawled {len(self.crawled_urls)} pages...", int(progress))
        
        return self.results
    
    async def _crawl_url(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, 
                        url: str, depth: int, inputs: Dict[str, Any]):
        """Crawl a single URL."""
        async with semaphore:
            if url in self.crawled_urls:
                return
            
            try:
                # Check robots.txt
                if inputs.get('respect_robots', True) and not self._is_allowed_by_robots(url):
                    return
                
                start_time = time.time()
                
                async with session.get(url, allow_redirects=inputs.get('follow_redirects', True)) as response:
                    content = await response.text(errors='replace')
                    response_time = time.time() - start_time
                    
                    # Create crawl result
                    result = CrawlResult(
                        url=str(response.url),
                        status_code=response.status,
                        content=content,
                        headers=dict(response.headers)
                    )
                    result.response_time = response_time
                    
                    # Extract data from page
                    result.extract_data()
                    
                    # Store result
                    self.results[url] = result
                    self.crawled_urls.add(url)
                    
                    # Update statistics
                    self.stats['total_urls_crawled'] += 1
                    self.stats['total_forms_found'] += len(result.forms)
                    self.stats['total_parameters_found'] += len(result.parameters)
                    self.stats['technologies_detected'].update(result.technologies)
                    
                    # Add new URLs to queue
                    if depth < inputs.get('crawl_depth', 3):
                        await self._extract_and_queue_links(result, depth + 1, inputs)
                
            except Exception as e:
                self.logger.error(f"Error crawling {url}: {e}")
                self.stats['total_errors'] += 1
                
                # Store error result
                error_result = CrawlResult(url=url, status_code=0)
                error_result.content = f"Error: {str(e)}"
                self.results[url] = error_result
                self.crawled_urls.add(url)
    
    async def _extract_and_queue_links(self, result: CrawlResult, next_depth: int, inputs: Dict[str, Any]):
        """Extract links from crawled page and add to queue."""
        base_url = result.url
        parsed_base = urlparse(base_url)
        
        for link in result.links:
            try:
                # Resolve relative URLs
                absolute_url = urljoin(base_url, link)
                parsed_link = urlparse(absolute_url)
                
                # Skip non-HTTP(S) URLs
                if parsed_link.scheme not in ['http', 'https']:
                    continue
                
                # Skip external links if not configured to crawl them
                if not inputs.get('crawl_external_links', False):
                    if parsed_link.netloc != parsed_base.netloc:
                        continue
                
                # Skip already crawled URLs
                if absolute_url in self.crawled_urls:
                    continue
                
                # Skip URLs already in queue
                if any(absolute_url == queued_url for queued_url, _ in self.url_queue):
                    continue
                
                # Add to queue
                self.url_queue.append((absolute_url, next_depth))
                self.stats['total_urls_found'] += 1
                
            except Exception as e:
                self.logger.debug(f"Error processing link {link}: {e}")
    
    async def _fetch_robots_txt(self, base_url: str):
        """Fetch and parse robots.txt."""
        try:
            parsed_url = urlparse(base_url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(robots_url) as response:
                    if response.status == 200:
                        robots_content = await response.text()
                        self.robots_txt = self._parse_robots_txt(robots_content)
        
        except Exception as e:
            self.logger.debug(f"Could not fetch robots.txt: {e}")
    
    def _parse_robots_txt(self, content: str) -> Dict[str, List[str]]:
        """Parse robots.txt content."""
        robots = {'disallow': [], 'allow': []}
        
        for line in content.split('\n'):
            line = line.strip().lower()
            if line.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    robots['disallow'].append(path)
            elif line.startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    robots['allow'].append(path)
        
        return robots
    
    def _is_allowed_by_robots(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if not self.robots_txt:
            return True
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # Check disallow rules
        for disallow_path in self.robots_txt.get('disallow', []):
            if path.startswith(disallow_path):
                return False
        
        return True
    
    async def _fetch_sitemap(self, base_url: str):
        """Fetch and parse sitemap.xml."""
        try:
            parsed_url = urlparse(base_url)
            sitemap_url = f"{parsed_url.scheme}://{parsed_url.netloc}/sitemap.xml"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(sitemap_url) as response:
                    if response.status == 200:
                        sitemap_content = await response.text()
                        self.sitemap_urls = self._parse_sitemap(sitemap_content)
                        
                        # Add sitemap URLs to queue
                        for url in self.sitemap_urls:
                            if url not in self.crawled_urls:
                                self.url_queue.append((url, 0))
        
        except Exception as e:
            self.logger.debug(f"Could not fetch sitemap.xml: {e}")
    
    def _parse_sitemap(self, content: str) -> Set[str]:
        """Parse sitemap.xml content."""
        urls = set()
        
        # Simple regex-based parsing
        url_pattern = re.compile(r'<loc>(.*?)</loc>', re.IGNORECASE)
        urls.update(url_pattern.findall(content))
        
        return urls
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate crawling statistics."""
        if not self.results:
            return {}
        
        response_times = [r.response_time for r in self.results.values() if r.response_time > 0]
        status_codes = [r.status_code for r in self.results.values()]
        
        return {
            'total_urls_found': self.stats['total_urls_found'],
            'total_urls_crawled': self.stats['total_urls_crawled'],
            'total_forms_found': self.stats['total_forms_found'],
            'total_parameters_found': self.stats['total_parameters_found'],
            'total_errors': self.stats['total_errors'],
            'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'status_code_distribution': dict(Counter(status_codes)),
            'technologies_detected': list(self.stats['technologies_detected']),
            'unique_parameters': len(set().union(*[r.parameters for r in self.results.values()])),
            'pages_with_forms': len([r for r in self.results.values() if r.forms]),
            'pages_with_comments': len([r for r in self.results.values() if r.comments]),
            'external_resources': len(set().union(*[r.scripts + r.styles + r.images for r in self.results.values()]))
        }
    
    def _generate_site_map(self) -> Dict[str, Any]:
        """Generate site map from crawled URLs."""
        site_map = {
            'structure': defaultdict(list),
            'depth_distribution': defaultdict(int),
            'file_types': defaultdict(int)
        }
        
        for url, result in self.results.items():
            parsed_url = urlparse(url)
            path_parts = [p for p in parsed_url.path.split('/') if p]
            
            # Build directory structure
            current_level = site_map['structure']
            for part in path_parts[:-1]:  # All but the last part
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]
            
            # Add file/page
            if path_parts:
                filename = path_parts[-1] if path_parts else 'index'
                if isinstance(current_level, dict):
                    current_level[filename] = {
                        'url': url,
                        'status': result.status_code,
                        'size': result.content_length
                    }
            
            # Track depth
            depth = len(path_parts)
            site_map['depth_distribution'][depth] += 1
            
            # Track file types
            if '.' in parsed_url.path:
                extension = parsed_url.path.split('.')[-1].lower()
                site_map['file_types'][extension] += 1
            else:
                site_map['file_types']['html'] += 1
        
        return dict(site_map)
    
    def _analyze_forms(self) -> Dict[str, Any]:
        """Analyze forms found during crawling."""
        all_forms = []
        for result in self.results.values():
            for form in result.forms:
                form_analysis = form.copy()
                form_analysis['page_url'] = result.url
                form_analysis['security_issues'] = []
                
                # Check for security issues
                if form['method'].upper() == 'GET' and any(inp['type'] == 'password' for inp in form['inputs']):
                    form_analysis['security_issues'].append('Password field in GET form')
                
                if not any(inp['type'] == 'hidden' and 'token' in inp['name'].lower() for inp in form['inputs']):
                    form_analysis['security_issues'].append('No CSRF token detected')
                
                all_forms.append(form_analysis)
        
        return {
            'total_forms': len(all_forms),
            'forms_by_method': dict(Counter(f['method'] for f in all_forms)),
            'forms_with_security_issues': len([f for f in all_forms if f['security_issues']]),
            'common_input_names': dict(Counter([
                inp['name'] for form in all_forms 
                for inp in form['inputs'] 
                if inp['name']
            ]).most_common(10)),
            'detailed_forms': all_forms
        }
    
    def _analyze_parameters(self) -> Dict[str, Any]:
        """Analyze parameters found during crawling."""
        all_parameters = set()
        parameter_sources = defaultdict(list)
        
        for result in self.results.values():
            for param in result.parameters:
                all_parameters.add(param)
                parameter_sources[param].append(result.url)
        
        return {
            'total_unique_parameters': len(all_parameters),
            'parameters_list': list(all_parameters),
            'parameter_frequency': {
                param: len(sources) for param, sources in parameter_sources.items()
            },
            'most_common_parameters': list(sorted(
                parameter_sources.items(), 
                key=lambda x: len(x[1]), 
                reverse=True
            ))[:20]
        }
    
    def _analyze_security(self) -> Dict[str, Any]:
        """Analyze security aspects of crawled pages."""
        security_analysis = {
            'missing_security_headers': defaultdict(int),
            'insecure_forms': [],
            'mixed_content': [],
            'information_disclosure': [],
            'security_score': 0.0
        }
        
        total_pages = len(self.results)
        if total_pages == 0:
            return security_analysis
        
        for result in self.results.values():
            # Check security headers
            required_headers = [
                'Content-Security-Policy', 'X-Frame-Options', 
                'X-Content-Type-Options', 'X-XSS-Protection'
            ]
            
            for header in required_headers:
                if header not in result.security_headers:
                    security_analysis['missing_security_headers'][header] += 1
            
            # Check for information disclosure in comments
            for comment in result.comments:
                if any(keyword in comment.lower() for keyword in ['password', 'key', 'secret', 'token', 'api']):
                    security_analysis['information_disclosure'].append({
                        'url': result.url,
                        'type': 'sensitive_comment',
                        'content': comment[:100] + '...' if len(comment) > 100 else comment
                    })
        
        # Calculate security score
        header_score = 1.0 - (sum(security_analysis['missing_security_headers'].values()) / (total_pages * len(required_headers)))
        security_analysis['security_score'] = max(0.0, header_score)
        
        return security_analysis
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate security and optimization recommendations."""
        recommendations = []
        
        # Security recommendations
        security_analysis = self._analyze_security()
        if security_analysis['missing_security_headers']:
            recommendations.append({
                'category': 'security',
                'priority': 'high',
                'recommendation': 'Implement missing security headers',
                'rationale': f"Security headers missing on multiple pages: {', '.join(security_analysis['missing_security_headers'].keys())}"
            })
        
        # Form security
        forms_analysis = self._analyze_forms()
        if forms_analysis['forms_with_security_issues'] > 0:
            recommendations.append({
                'category': 'security',
                'priority': 'high',
                'recommendation': 'Review and secure forms',
                'rationale': f"{forms_analysis['forms_with_security_issues']} forms have potential security issues"
            })
        
        # Performance recommendations
        stats = self._generate_statistics()
        if stats.get('average_response_time', 0) > 3.0:
            recommendations.append({
                'category': 'performance',
                'priority': 'medium',
                'recommendation': 'Optimize page load times',
                'rationale': f"Average response time is {stats['average_response_time']:.2f} seconds"
            })
        
        # Information architecture
        if stats.get('total_errors', 0) > 0:
            recommendations.append({
                'category': 'maintenance',
                'priority': 'medium',
                'recommendation': 'Fix broken links and pages',
                'rationale': f"{stats['total_errors']} pages returned errors during crawling"
            })
        
        return recommendations
