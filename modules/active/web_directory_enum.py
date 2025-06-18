"""
Web Directory Enumeration Module
Performs web directory and file discovery through brute forcing.
"""

import logging
import aiohttp
import asyncio
import time
import os
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from modules.base_module import BaseModule


class WebDirectoryEnumerationModule(BaseModule):
    """Web directory and file enumeration module."""
    
    def __init__(self):
        super().__init__(
            name="Web Directory Enumeration",
            description="Discover hidden directories and files on web servers",
            category="active"
        )
        
        self.logger = logging.getLogger(__name__)
        self._stop_requested = False
        self._found_urls = set()
        self._processed_count = 0
        self._total_count = 0
        self._start_time = 0
    
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
                'placeholder': 'https://example.com'
            },
            {
                'name': 'wordlist',
                'type': 'file',
                'label': 'Wordlist',
                'required': False,
                'default': '',
                'placeholder': 'Select a wordlist file or use default'
            },
            {
                'name': 'extensions',
                'type': 'text',
                'label': 'File Extensions',
                'required': False,
                'default': 'php,html,js,txt',
                'placeholder': 'e.g., php,html,asp,aspx'
            },
            {
                'name': 'recursive',
                'type': 'checkbox',
                'label': 'Recursive Scanning',
                'required': False,
                'default': False
            },
            {
                'name': 'follow_redirects',
                'type': 'checkbox',
                'label': 'Follow Redirects',
                'required': False,
                'default': True
            },
            {
                'name': 'threads',
                'type': 'number',
                'label': 'Concurrent Requests',
                'required': False,
                'default': 30,
                'min': 1,
                'max': 100
            },
            {
                'name': 'status_codes',
                'type': 'text',
                'label': 'Status Codes to Include',
                'required': False,
                'default': '200,201,202,203,204,301,302,307,401,403',
                'placeholder': 'e.g., 200,301,302,403'
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
        
        threads = inputs.get('threads', 30)
        try:
            threads_int = int(threads)
            if threads_int < 1 or threads_int > 100:
                return "Threads must be between 1 and 100"
        except ValueError:
            return "Threads must be a number"
        
        wordlist_path = inputs.get('wordlist', '')
        if wordlist_path and not os.path.isfile(wordlist_path):
            return f"Wordlist file does not exist: {wordlist_path}"
        
        return None
    
    async def fetch_url(self, session: aiohttp.ClientSession, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Fetch a URL and return information about the response.
        
        Args:
            session: HTTP session
            url: URL to fetch
            follow_redirects: Whether to follow redirects
            
        Returns:
            Dict with URL status information
        """
        if self._stop_requested:
            return None
            
        try:
            start_time = time.time()
            async with session.get(
                url, 
                allow_redirects=follow_redirects, 
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False  # Disable SSL verification for testing
            ) as response:
                elapsed = time.time() - start_time
                size = len(await response.read())
                
                return {
                    'url': url,
                    'status_code': response.status,
                    'content_type': response.headers.get('Content-Type', ''),
                    'size': size,
                    'elapsed': elapsed,
                    'redirect_url': str(response.url) if str(response.url) != url else None
                }
        except asyncio.TimeoutError:
            return {
                'url': url,
                'status_code': 0,
                'content_type': '',
                'size': 0,
                'elapsed': 10.0,
                'error': 'Timeout'
            }
        except aiohttp.ClientError as e:
            return {
                'url': url,
                'status_code': 0,
                'content_type': '',
                'size': 0,
                'elapsed': time.time() - start_time,
                'error': str(e)
            }
        except Exception as e:
            self.logger.error(f"Error fetching {url}: {e}")
            return {
                'url': url,
                'status_code': 0,
                'content_type': '',
                'size': 0,
                'elapsed': time.time() - start_time,
                'error': str(e)
            }
        finally:
            self._processed_count += 1
            progress = int((self._processed_count / self._total_count) * 100)
            elapsed = time.time() - self._start_time
            remaining = (elapsed / self._processed_count) * (self._total_count - self._processed_count) if self._processed_count > 0 else 0
            self.update_progress(
                f"Scanning: {self._processed_count}/{self._total_count} URLs checked "
                f"({progress}%) - {self._found_urls and len(self._found_urls) or 0} found "
                f"[ETA: {int(remaining/60)}m {int(remaining%60)}s]", 
                progress
            )
    
    async def process_batch(self, session: aiohttp.ClientSession, urls: List[str], follow_redirects: bool, status_codes: List[int]) -> List[Dict[str, Any]]:
        """Process a batch of URLs concurrently."""
        if self._stop_requested:
            return []
        
        tasks = [self.fetch_url(session, url, follow_redirects) for url in urls]
        results = await asyncio.gather(*tasks)
        
        # Filter results based on status codes
        filtered_results = []
        for result in results:
            if result and result['status_code'] in status_codes:
                self._found_urls.add(result['url'])
                filtered_results.append(result)
        
        return filtered_results
    
    def get_default_wordlist(self) -> List[str]:
        """Get the default wordlist for web directory enumeration."""
        wordlist = [
            # Common directories
            "admin", "administrator", "backup", "backups", "config", "dashboard",
            "db", "dump", "files", "forum", "forums", "home", "img", "images",
            "index", "js", "login", "logs", "old", "panel", "phpmyadmin",
            "private", "root", "secret", "secure", "security", "server-status",
            "temp", "test", "tmp", "upload", "uploads", "user", "users", "wp-admin",
            "wp-content", "wp-includes", "bak", "beta", "dev", "api", 
            "install", "setup", "admin.php", "login.php", "wp-login.php",
            ".git", ".svn", ".DS_Store", "info.php", "phpinfo.php",
            "robots.txt", "sitemap.xml", "server-info", "debug", 
            "cache", "cgi-bin", "css", "download", "downloads", 
            "mail", "webmail", "static", "assets", "javascript",
            "register", "sign-up", "signup", "account", "manage",
            "control", "member", "members", "content", "archive",
            "password", "authenticate", "auth", "portal", "tools",
            "database", "conf", "config.php", "config.inc.php",
            ".env", ".htaccess", "web.config", "app", "site",
            "mobile", "help", "support", "faq", "contact",
            "about", "demo", "examples", "sample", "media",
            "docs", "doc", "api/v1", "api/v2", "data",
            "public", "src", "scripts", "script", "vendor"
        ]
        return wordlist
    
    async def enumerate_directories(self, base_url: str, wordlist: List[str], extensions: List[str], 
                                   batch_size: int, follow_redirects: bool, status_codes: List[int]) -> List[Dict[str, Any]]:
        """
        Enumerate directories by making requests to the target.
        
        Args:
            base_url: Base URL to scan
            wordlist: List of directory/file names to check
            extensions: List of file extensions to append
            batch_size: Number of concurrent requests
            follow_redirects: Whether to follow redirects
            status_codes: List of status codes to consider as "found"
            
        Returns:
            List of found URLs with their details
        """
        # Ensure base_url ends with a slash
        if not base_url.endswith('/'):
            base_url += '/'
            
        # Generate all URLs to test
        urls_to_test = []
        
        # Add directories first (no extension)
        for word in wordlist:
            if word:
                # Skip comments and empty lines
                if word.startswith('#') or word.strip() == '':
                    continue
                    
                # Normalize path
                word = word.strip('/ \t\n\r')
                if word:
                    urls_to_test.append(f"{base_url}{word}/")
        
        # Add files with extensions
        for word in wordlist:
            if word:
                # Skip comments and empty lines
                if word.startswith('#') or word.strip() == '':
                    continue
                    
                # Normalize path
                word = word.strip('/ \t\n\r')
                if word:
                    # Add the word without extension
                    urls_to_test.append(f"{base_url}{word}")
                    
                    # Add with extensions
                    for ext in extensions:
                        if ext:
                            ext = ext.strip('. \t\n\r')
                            if ext:
                                urls_to_test.append(f"{base_url}{word}.{ext}")
        
        self._total_count = len(urls_to_test)
        self._processed_count = 0
        self._start_time = time.time()
        self.logger.info(f"Starting web directory enumeration on {base_url} with {self._total_count} paths")
        
        # Initialize results
        found_urls = []
        
        # Create a ClientSession with appropriate headers
        async with aiohttp.ClientSession(
            headers={
                'User-Agent': self.get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Pragma': 'no-cache',
                'Cache-Control': 'no-cache'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            # Process URLs in batches
            for i in range(0, len(urls_to_test), batch_size):
                if self._stop_requested:
                    break
                
                batch = urls_to_test[i:i+batch_size]
                batch_results = await self.process_batch(session, batch, follow_redirects, status_codes)
                found_urls.extend(batch_results)
        
        return found_urls
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run web directory enumeration scan.
        
        Args:
            inputs (Dict[str, Any]): Input parameters
            config (Dict[str, Any]): Configuration parameters
            
        Returns:
            Dict[str, Any]: Scan results
        """
        self._stop_requested = False
        self._found_urls = set()
        
        target_url = inputs.get('target_url', '').rstrip('/')
        wordlist_path = inputs.get('wordlist', '')
        extensions_str = inputs.get('extensions', 'php,html,js,txt')
        recursive = inputs.get('recursive', False)
        follow_redirects = inputs.get('follow_redirects', True)
        threads = int(inputs.get('threads', 30))
        status_codes_str = inputs.get('status_codes', '200,201,202,203,204,301,302,307,401,403')
        
        # Parse extensions
        extensions = [ext.strip() for ext in extensions_str.split(',') if ext.strip()]
        
        # Parse status codes
        try:
            status_codes = [int(code.strip()) for code in status_codes_str.split(',') if code.strip()]
        except ValueError:
            self.logger.error("Invalid status codes provided, using defaults")
            status_codes = [200, 201, 202, 203, 204, 301, 302, 307, 401, 403]
        
        # Load wordlist
        wordlist = []
        if wordlist_path and os.path.isfile(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f.readlines()]
            except Exception as e:
                self.logger.error(f"Error reading wordlist file: {e}")
                wordlist = self.get_default_wordlist()
        else:
            wordlist = self.get_default_wordlist()
        
        self.logger.info(f"Using wordlist with {len(wordlist)} entries")
        self.update_progress(f"Starting web directory enumeration on {target_url}", 0)
        
        try:
            # Create event loop and run the async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            start_time = time.time()
            found_urls = loop.run_until_complete(self.enumerate_directories(
                target_url, wordlist, extensions, threads, follow_redirects, status_codes
            ))
            scan_time = time.time() - start_time
            loop.close()
            
            # Process and format results
            results = {
                'scan_info': {
                    'target_url': target_url,
                    'total_paths_checked': self._total_count,
                    'scan_time': f"{scan_time:.2f} seconds",
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'wordlist': wordlist_path or "Default wordlist",
                    'wordlist_size': len(wordlist),
                    'extensions': extensions_str,
                    'threads': threads,
                    'recursive': recursive,
                    'follow_redirects': follow_redirects,
                    'status_codes': status_codes_str
                },
                'results': {
                    'total_found': len(found_urls),
                    'found_urls': found_urls
                }
            }
            
            # Add summary for quick reference
            results['summary'] = {
                'target_url': target_url,
                'total_checked': self._total_count,
                'total_found': len(found_urls),
                'scan_duration': f"{scan_time:.2f} seconds"
            }
            
            # Sort results by status code for better readability
            found_urls.sort(key=lambda x: (x['status_code'], x['url']))
            
            self.update_progress(f"Scan completed: Found {len(found_urls)} resources on {target_url}", 100)
            return results
            
        except Exception as e:
            self.logger.error(f"Web directory enumeration error: {str(e)}")
            raise Exception(f"Web directory enumeration error: {str(e)}")
    
    def stop_scan(self):
        """Stop the current scan operation."""
        self._stop_requested = True
        super().stop_scan()
