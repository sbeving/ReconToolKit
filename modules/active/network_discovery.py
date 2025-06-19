"""
Network Discovery Module
Advanced network discovery and host enumeration.
"""

import logging
import asyncio
import socket
import struct
import ipaddress
import time
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from modules.base_module import BaseModule


class NetworkDiscoveryModule(BaseModule):
    """Advanced network discovery and host enumeration."""
    
    def __init__(self):
        super().__init__(
            name="Network Discovery",
            description="Comprehensive network discovery including host enumeration, service detection, and OS fingerprinting",
            category="active"
        )
        
        self.logger = logging.getLogger(__name__)
        self._stop_requested = False
        self._discovered_hosts = set()
        
        # Common ports for service detection
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
        ]
        
        # OS fingerprinting signatures
        self.os_signatures = {
            'windows': ['microsoft', 'windows', 'iis', 'asp.net', 'sharepoint'],
            'linux': ['apache', 'nginx', 'openssh', 'bind', 'postfix'],
            'unix': ['sendmail', 'apache', 'bind'],
            'cisco': ['cisco', 'ios'],
            'juniper': ['junos', 'juniper']
        }

    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'target_network',
                'type': 'text',
                'label': 'Target Network/Range',
                'required': True,
                'default': '',
                'placeholder': '192.168.1.0/24 or 10.0.0.1-10.0.0.100'
            },
            {
                'name': 'discovery_method',
                'type': 'combo',
                'label': 'Discovery Method',
                'required': False,
                'default': 'ping_sweep',
                'options': ['ping_sweep', 'tcp_connect', 'syn_scan', 'udp_scan', 'arp_scan'],
                'tooltip': 'Method used for host discovery'
            },
            {
                'name': 'port_scan',
                'type': 'checkbox',
                'label': 'Enable Port Scanning',
                'required': False,
                'default': True
            },
            {
                'name': 'port_range',
                'type': 'text',
                'label': 'Port Range',
                'required': False,
                'default': '1-1000',
                'placeholder': '1-1000 or 21,22,80,443'
            },
            {
                'name': 'service_detection',
                'type': 'checkbox',
                'label': 'Service Detection',
                'required': False,
                'default': True
            },
            {
                'name': 'os_detection',
                'type': 'checkbox',
                'label': 'OS Detection',
                'required': False,
                'default': True
            },
            {
                'name': 'aggressive_scan',
                'type': 'checkbox',
                'label': 'Aggressive Scanning',
                'required': False,
                'default': False,
                'tooltip': 'More thorough but potentially detectable scanning'
            },
            {
                'name': 'threads',
                'type': 'number',
                'label': 'Concurrent Threads',
                'required': False,
                'default': 50,
                'min': 1,
                'max': 200
            },
            {
                'name': 'timeout',
                'type': 'number',
                'label': 'Connection Timeout (seconds)',
                'required': False,
                'default': 3,
                'min': 1,
                'max': 30
            }
        ]

    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        target_network = inputs.get('target_network', '').strip()
        if not target_network:
            return "Target network/range is required"
        
        # Validate network format
        try:
            if '/' in target_network:
                ipaddress.ip_network(target_network, strict=False)
            elif '-' in target_network:
                start_ip, end_ip = target_network.split('-')
                ipaddress.ip_address(start_ip.strip())
                ipaddress.ip_address(end_ip.strip())
            else:
                ipaddress.ip_address(target_network)
        except ValueError:
            return "Invalid network format. Use CIDR notation (192.168.1.0/24) or range (192.168.1.1-192.168.1.100)"
        
        return None

    def parse_target_network(self, target_network: str) -> List[str]:
        """Parse target network into list of IP addresses."""
        ips = []
        
        try:
            if '/' in target_network:
                # CIDR notation
                network = ipaddress.ip_network(target_network, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            elif '-' in target_network:
                # IP range
                start_ip, end_ip = target_network.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
            else:
                # Single IP
                ips = [target_network]
                
        except Exception as e:
            self.logger.error(f"Error parsing target network: {e}")
        
        return ips

    def parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range into list of ports."""
        ports = []
        
        try:
            if ',' in port_range:
                # Comma-separated ports
                for port_item in port_range.split(','):
                    port_item = port_item.strip()
                    if '-' in port_item:
                        start, end = map(int, port_item.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(port_item))
            elif '-' in port_range:
                # Port range
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
            else:
                # Single port
                ports = [int(port_range)]
                
        except Exception as e:
            self.logger.error(f"Error parsing port range: {e}")
            ports = self.common_ports
        
        return ports

    async def ping_host(self, ip: str, timeout: int) -> bool:
        """Ping a host to check if it's alive."""
        try:
            # Use asyncio subprocess for ping
            if hasattr(asyncio, 'create_subprocess_exec'):
                process = await asyncio.create_subprocess_exec(
                    'ping', '-n', '1', '-w', str(timeout * 1000), ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                return process.returncode == 0
            else:
                # Fallback to socket-based check
                return await self.tcp_connect_check(ip, 80, timeout)
        except Exception:
            return False

    async def tcp_connect_check(self, ip: str, port: int, timeout: int) -> bool:
        """Check if a TCP port is open."""
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def scan_port(self, ip: str, port: int, timeout: int) -> Dict[str, Any]:
        """Scan a single port on a host."""
        try:
            start_time = time.time()
            
            # Try TCP connection
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            
            response_time = (time.time() - start_time) * 1000  # ms
            
            # Try to grab banner
            banner = ""
            try:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'port': port,
                'state': 'open',
                'protocol': 'tcp',
                'service': self.identify_service(port, banner),
                'banner': banner[:200] if banner else '',
                'response_time': round(response_time, 2)
            }
            
        except Exception:
            return {
                'port': port,
                'state': 'closed',
                'protocol': 'tcp',
                'service': '',
                'banner': '',
                'response_time': 0
            }

    def identify_service(self, port: int, banner: str) -> str:
        """Identify service based on port and banner."""
        # Common port-to-service mapping
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 1723: 'pptp', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
        }
        
        service = common_services.get(port, f'unknown-{port}')
        
        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if 'http' in banner_lower:
                service = 'http'
            elif 'ftp' in banner_lower:
                service = 'ftp'
            elif 'ssh' in banner_lower:
                service = 'ssh'
            elif 'smtp' in banner_lower:
                service = 'smtp'
            elif 'mysql' in banner_lower:
                service = 'mysql'
            elif 'postgresql' in banner_lower:
                service = 'postgresql'
        
        return service

    def detect_os(self, host_info: Dict[str, Any]) -> str:
        """Detect operating system based on service fingerprints."""
        open_ports = host_info.get('open_ports', [])
        banners = ' '.join([port.get('banner', '') for port in open_ports]).lower()
        
        os_scores = {os_name: 0 for os_name in self.os_signatures}
        
        for os_name, signatures in self.os_signatures.items():
            for signature in signatures:
                if signature in banners:
                    os_scores[os_name] += 1
        
        # Determine most likely OS
        if max(os_scores.values()) > 0:
            return max(os_scores, key=os_scores.get)
        
        # Fallback based on common port patterns
        port_numbers = [port['port'] for port in open_ports if port['state'] == 'open']
        
        if 3389 in port_numbers or 135 in port_numbers:
            return 'windows'
        elif 22 in port_numbers:
            return 'linux'
        elif 111 in port_numbers:
            return 'unix'
        
        return 'unknown'

    async def discover_hosts(self, target_ips: List[str], method: str, timeout: int) -> List[str]:
        """Discover live hosts using specified method."""
        live_hosts = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def check_host(ip: str):
            async with semaphore:
                if not self.should_continue():
                    return
                
                is_alive = False
                
                if method == 'ping_sweep':
                    is_alive = await self.ping_host(ip, timeout)
                elif method == 'tcp_connect':
                    # Check common ports
                    for port in [80, 443, 22, 21, 23]:
                        if await self.tcp_connect_check(ip, port, timeout):
                            is_alive = True
                            break
                elif method == 'syn_scan':
                    # Simplified SYN scan (actually TCP connect for this implementation)
                    is_alive = await self.tcp_connect_check(ip, 80, timeout)
                
                if is_alive:
                    live_hosts.append(ip)
                    self._discovered_hosts.add(ip)
        
        # Run host discovery
        tasks = [check_host(ip) for ip in target_ips]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))

    async def scan_host(self, ip: str, ports: List[int], timeout: int, 
                       service_detection: bool) -> Dict[str, Any]:
        """Scan a single host for open ports and services."""
        host_info = {
            'ip': ip,
            'hostname': '',
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'os': 'unknown',
            'scan_time': time.time()
        }
        
        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            host_info['hostname'] = hostname
        except Exception:
            pass
        
        # Scan ports
        semaphore = asyncio.Semaphore(20)  # Limit concurrent port scans
        
        async def scan_single_port(port: int):
            async with semaphore:
                if not self.should_continue():
                    return
                
                port_info = await self.scan_port(ip, port, timeout)
                
                if port_info['state'] == 'open':
                    host_info['open_ports'].append(port_info)
                else:
                    host_info['closed_ports'].append(port_info)
        
        # Run port scans
        tasks = [scan_single_port(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # OS detection
        if service_detection and host_info['open_ports']:
            host_info['os'] = self.detect_os(host_info)
        
        return host_info

    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run the network discovery scan."""
        target_network = inputs.get('target_network').strip()
        discovery_method = inputs.get('discovery_method', 'ping_sweep')
        port_scan = inputs.get('port_scan', True)
        port_range = inputs.get('port_range', '1-1000')
        service_detection = inputs.get('service_detection', True)
        os_detection = inputs.get('os_detection', True)
        aggressive_scan = inputs.get('aggressive_scan', False)
        threads = inputs.get('threads', 50)
        timeout = inputs.get('timeout', 3)
        
        start_time = time.time()
        self._stop_requested = False
        self._discovered_hosts = set()
        
        # Parse targets and ports
        target_ips = self.parse_target_network(target_network)
        ports = self.parse_port_range(port_range) if port_scan else []
        
        self.update_progress(f"Scanning {len(target_ips)} hosts...", 10)
        
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                self._run_async_discovery(target_ips, ports, discovery_method, 
                                        service_detection, timeout)
            )
        finally:
            loop.close()
        
        scan_time = time.time() - start_time
        
        # Generate summary
        total_hosts = len(results.get('hosts', []))
        live_hosts = len([h for h in results.get('hosts', []) if h.get('open_ports')])
        total_open_ports = sum(len(h.get('open_ports', [])) for h in results.get('hosts', []))
        
        results['summary'] = {
            'target_network': target_network,
            'total_ips_scanned': len(target_ips),
            'live_hosts': live_hosts,
            'total_hosts_found': total_hosts,
            'total_open_ports': total_open_ports,
            'scan_time': round(scan_time, 2),
            'discovery_method': discovery_method,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return results

    async def _run_async_discovery(self, target_ips: List[str], ports: List[int], 
                                 discovery_method: str, service_detection: bool, 
                                 timeout: int) -> Dict[str, Any]:
        """Run the async network discovery."""
        
        # Host discovery phase
        self.update_progress("Discovering live hosts...", 20)
        live_hosts = await self.discover_hosts(target_ips, discovery_method, timeout)
        
        self.update_progress(f"Found {len(live_hosts)} live hosts, scanning ports...", 40)
        
        # Port scanning phase
        results = {'hosts': []}
        
        if ports and live_hosts:
            semaphore = asyncio.Semaphore(10)  # Limit concurrent host scans
            
            async def scan_single_host(ip: str):
                async with semaphore:
                    if not self.should_continue():
                        return None
                    
                    host_info = await self.scan_host(ip, ports, timeout, service_detection)
                    return host_info
            
            # Scan all live hosts
            tasks = [scan_single_host(ip) for ip in live_hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and exceptions
            results['hosts'] = [r for r in host_results if r and not isinstance(r, Exception)]
        else:
            # No port scanning, just return discovered hosts
            results['hosts'] = [{'ip': ip, 'hostname': '', 'open_ports': [], 'os': 'unknown'} 
                              for ip in live_hosts]
        
        self.update_progress("Network discovery completed", 100)
        return results

    def stop_scan(self):
        """Stop the network discovery scan."""
        self._stop_requested = True
        self.logger.info("Network discovery scan stop requested")
