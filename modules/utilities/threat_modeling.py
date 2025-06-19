"""
Threat Modeling and Attack Surface Analysis Module
Advanced threat modeling and attack surface analysis capabilities.
"""

import logging
import json
import time
import aiohttp
from typing import Dict, List, Any, Optional
import socket

from modules.base_module import BaseModule


class ThreatModelingModule(BaseModule):
    """Advanced threat modeling and attack surface analysis module."""
    
    def __init__(self):
        """Initialize the threat modeling module."""
        super().__init__(
            name="Threat Modeling & Attack Surface Analysis",
            description="Advanced threat modeling and comprehensive attack surface analysis",
            category="utilities"
        )
        self.author = "ReconToolKit Team"
        self.version = "1.0.0"
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        """Get input fields for the module."""
        return [
            {
                'name': 'target',
                'type': 'text',
                'label': 'Target',
                'required': True,
                'placeholder': 'example.com or 192.168.1.1',
                'help': 'Target domain or IP address for analysis'
            },
            {
                'name': 'analysis_depth',
                'type': 'select',
                'label': 'Analysis Depth',
                'options': ['basic', 'comprehensive', 'deep'],
                'default': 'basic',
                'help': 'Depth of threat analysis to perform'
            }
        ]
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run threat modeling and attack surface analysis.
        
        Args:
            inputs: User inputs from the form
            config: Module configuration
            
        Returns:
            Dictionary containing threat model and attack surface analysis
        """
        try:
            target = inputs.get('target', '')
            analysis_depth = inputs.get('analysis_depth', 'basic')
            
            self.logger.info(f"Starting threat modeling for {target}")
            
            results = {
                'target': target,
                'analysis_depth': analysis_depth,
                'timestamp': time.time(),
                'attack_surface': {},
                'threat_model': {},
                'risk_assessment': {},
                'vulnerabilities': [],
                'recommendations': [],
                'summary': f"Threat modeling analysis completed for {target}"
            }
            
            # Basic network analysis
            try:
                ip = socket.gethostbyname(target)
                results['attack_surface']['ip_address'] = ip
                results['attack_surface']['resolved'] = True
                
                # Basic port scan for common ports
                open_ports = []
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        continue
                
                results['attack_surface']['open_ports'] = open_ports
                results['attack_surface']['port_count'] = len(open_ports)
                
            except Exception as e:
                results['attack_surface']['resolved'] = False
                results['attack_surface']['error'] = str(e)
            
            # Basic threat assessment
            threat_score = 5  # Medium baseline
            if results['attack_surface'].get('port_count', 0) > 5:
                threat_score += 2
            if 22 in results['attack_surface'].get('open_ports', []):  # SSH
                threat_score += 1
            if 21 in results['attack_surface'].get('open_ports', []):  # FTP
                threat_score += 2
                
            results['risk_assessment']['overall_score'] = min(threat_score, 10)
            results['risk_assessment']['risk_level'] = self._get_risk_level(threat_score)
            
            # Basic recommendations
            recommendations = []
            if 21 in results['attack_surface'].get('open_ports', []):
                recommendations.append("Consider securing or disabling FTP service")
            if len(results['attack_surface'].get('open_ports', [])) > 5:
                recommendations.append("Review and minimize exposed services")
            
            results['recommendations'] = recommendations
            
            self.logger.info(f"Threat modeling completed for {target}")
            return results
            
        except Exception as e:
            error_msg = f"Error in threat modeling: {str(e)}"
            self.logger.error(error_msg)
            return {
                'error': error_msg,
                'target': inputs.get('target', ''),
                'timestamp': time.time()
            }
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score."""
        if score >= 8:
            return 'high'
        elif score >= 6:
            return 'medium'
        else:
            return 'low'



    
    async def _map_attack_surface(self, config: Dict[str, Any], results: Dict[str, Any], session: aiohttp.ClientSession):
        """Map the attack surface of the target."""
        target = config['target']
        attack_surface = {
            'network_assets': [],
            'web_applications': [],
            'services': [],
            'technologies': [],
            'entry_points': [],
            'data_flows': []
        }
        
        # Network discovery
        if config.get('include_network_scan', True):
            network_assets = await self._discover_network_assets(target)
            attack_surface['network_assets'] = network_assets
        
        # Web application discovery
        if config.get('include_web_analysis', True):
            web_apps = await self._discover_web_applications(target, session)
            attack_surface['web_applications'] = web_apps
        
        # Service enumeration
        services = await self._enumerate_services(target)
        attack_surface['services'] = services
        
        # Technology stack identification
        technologies = await self._identify_technologies(target, session)
        attack_surface['technologies'] = technologies
        
        # Entry point analysis
        entry_points = await self._analyze_entry_points(attack_surface)
        attack_surface['entry_points'] = entry_points
        
        # Data flow analysis
        data_flows = await self._analyze_data_flows(attack_surface)
        attack_surface['data_flows'] = data_flows
        
        results['attack_surface'] = attack_surface
    
    async def _discover_network_assets(self, target: str) -> List[Dict[str, Any]]:
        """Discover network assets."""
        assets = []
        
        try:
            # Parse target
            if '/' in target:  # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())[:254]  # Limit to prevent excessive scanning
            else:
                try:
                    # Try to resolve domain to IP
                    ip = socket.gethostbyname(target)
                    hosts = [ipaddress.ip_address(ip)]
                except socket.gaierror:
                    # Assume it's already an IP
                    hosts = [ipaddress.ip_address(target)]
            
            # Basic host discovery
            for host in hosts:
                try:
                    # Simple ping equivalent (attempt connection)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((str(host), 80))
                    sock.close()
                    
                    if result == 0:  # Host is up
                        assets.append({
                            'ip': str(host),
                            'status': 'up',
                            'hostname': self._reverse_dns_lookup(str(host))
                        })
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error in network discovery: {e}")
        
        return assets
    
    async def _discover_web_applications(self, target: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """Discover web applications."""
        web_apps = []
        
        protocols = ['http', 'https']
        ports = [80, 443, 8080, 8443, 3000, 8000]
        
        for protocol in protocols:
            for port in ports:
                if (protocol == 'http' and port in [80, 8080, 3000, 8000]) or \
                   (protocol == 'https' and port in [443, 8443]):
                    
                    url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
                    
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status < 400:
                                web_apps.append({
                                    'url': url,
                                    'status_code': response.status,
                                    'server': response.headers.get('Server', 'Unknown'),
                                    'technologies': self._detect_web_technologies(response.headers, await response.text()),
                                    'security_headers': self._analyze_security_headers(response.headers)
                                })
                    except Exception as e:
                        # Site not reachable on this port/protocol
                        continue
        
        return web_apps
    
    async def _enumerate_services(self, target: str) -> List[Dict[str, Any]]:
        """Enumerate services running on the target."""
        services = []
        
        try:
            # Common ports to check
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:  # Port is open
                        service_info = {
                            'port': port,
                            'state': 'open',
                            'service': self._identify_service(port),
                            'banner': await self._grab_banner(target, port)
                        }
                        services.append(service_info)
                    
                    sock.close()
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error enumerating services: {e}")
        
        return services
    
    async def _identify_technologies(self, target: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """Identify technologies used by the target."""
        technologies = []
        
        try:
            url = f"http://{target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                html = await response.text()
                headers = response.headers
                
                # Server identification
                server = headers.get('Server', '')
                if server:
                    technologies.append({
                        'name': server,
                        'category': 'Web Server',
                        'version': self._extract_version(server),
                        'confidence': 'high'
                    })
                
                # Framework detection
                frameworks = self._detect_frameworks(html, headers)
                technologies.extend(frameworks)
                
                # CMS detection
                cms = self._detect_cms(html)
                if cms:
                    technologies.append(cms)
                
        except Exception as e:
            self.logger.error(f"Error identifying technologies: {e}")
        
        return technologies
    
    async def _analyze_entry_points(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze potential entry points."""
        entry_points = []
        
        # Network entry points
        for asset in attack_surface.get('network_assets', []):
            entry_points.append({
                'type': 'network',
                'target': asset['ip'],
                'risk_level': 'medium',
                'description': f'Direct network access to {asset["ip"]}'
            })
        
        # Web application entry points
        for webapp in attack_surface.get('web_applications', []):
            risk_level = 'high' if webapp['url'].startswith('https://') else 'critical'
            entry_points.append({
                'type': 'web',
                'target': webapp['url'],
                'risk_level': risk_level,
                'description': f'Web application at {webapp["url"]}'
            })
        
        # Service entry points
        for service in attack_surface.get('services', []):
            risk_level = self._assess_service_risk(service)
            entry_points.append({
                'type': 'service',
                'target': f'{service["service"]}:{service["port"]}',
                'risk_level': risk_level,
                'description': f'{service["service"]} service on port {service["port"]}'
            })
        
        return entry_points
    
    async def _analyze_data_flows(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze data flows."""
        data_flows = []
        
        # Web application data flows
        for webapp in attack_surface.get('web_applications', []):
            data_flows.append({
                'source': 'user',
                'destination': webapp['url'],
                'data_type': 'HTTP requests/responses',
                'encryption': 'https' in webapp['url'],
                'risk_level': 'low' if 'https' in webapp['url'] else 'high'
            })
        
        # Database connections (inferred)
        database_services = [s for s in attack_surface.get('services', []) 
                           if s['service'] in ['mysql', 'postgresql', 'mssql', 'redis']]
        
        for db_service in database_services:
            data_flows.append({
                'source': 'application',
                'destination': f'{db_service["service"]}:{db_service["port"]}',
                'data_type': 'database queries',
                'encryption': 'unknown',
                'risk_level': 'medium'
            })
        
        return data_flows
    
    async def _generate_threat_model(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Generate threat model using STRIDE methodology."""
        threat_actors = config.get('threat_actors', ['script_kiddie', 'cybercriminal'])
        
        threat_model = {
            'methodology': 'STRIDE',
            'threat_actors': threat_actors,
            'threats': [],
            'attack_paths': [],
            'assets': self._identify_assets(results['attack_surface']),
            'trust_boundaries': self._identify_trust_boundaries(results['attack_surface'])
        }
        
        # STRIDE analysis
        stride_threats = await self._perform_stride_analysis(results['attack_surface'], threat_actors)
        threat_model['threats'] = stride_threats
        
        # Attack path analysis
        attack_paths = await self._analyze_attack_paths(results['attack_surface'], stride_threats)
        threat_model['attack_paths'] = attack_paths
        
        results['threat_model'] = threat_model
    
    async def _perform_stride_analysis(self, attack_surface: Dict[str, Any], threat_actors: List[str]) -> List[Dict[str, Any]]:
        """Perform STRIDE threat analysis."""
        threats = []
        
        stride_categories = {
            'Spoofing': 'Authentication',
            'Tampering': 'Integrity',
            'Repudiation': 'Non-repudiation',
            'Information Disclosure': 'Confidentiality',
            'Denial of Service': 'Availability',
            'Elevation of Privilege': 'Authorization'
        }
        
        for category, security_property in stride_categories.items():
            for entry_point in attack_surface.get('entry_points', []):
                threat = {
                    'category': category,
                    'security_property': security_property,
                    'target': entry_point['target'],
                    'description': f'{category} attack against {entry_point["target"]}',
                    'likelihood': self._assess_threat_likelihood(category, entry_point, threat_actors),
                    'impact': self._assess_threat_impact(category, entry_point),
                    'risk_score': 0,  # Will be calculated
                    'mitigation_strategies': self._get_mitigation_strategies(category, entry_point)
                }
                
                # Calculate risk score
                threat['risk_score'] = self._calculate_risk_score(threat['likelihood'], threat['impact'])
                threats.append(threat)
        
        return threats
    
    async def _analyze_attack_paths(self, attack_surface: Dict[str, Any], threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze potential attack paths."""
        attack_paths = []
        
        # Multi-step attack scenarios
        scenarios = [
            {
                'name': 'Web Application Compromise',
                'steps': [
                    'Reconnaissance of web application',
                    'Vulnerability identification',
                    'Exploitation (SQL injection, XSS, etc.)',
                    'Privilege escalation',
                    'Lateral movement'
                ],
                'likelihood': 'medium',
                'impact': 'high'
            },
            {
                'name': 'Network Infiltration',
                'steps': [
                    'Network discovery',
                    'Service enumeration',
                    'Exploit vulnerable service',
                    'Establish persistence',
                    'Data exfiltration'
                ],
                'likelihood': 'low',
                'impact': 'critical'
            },
            {
                'name': 'Social Engineering Attack',
                'steps': [
                    'Target identification',
                    'Information gathering',
                    'Phishing campaign',
                    'Credential theft',
                    'Account compromise'
                ],
                'likelihood': 'high',
                'impact': 'medium'
            }
        ]
        
        for scenario in scenarios:
            attack_paths.append({
                'name': scenario['name'],
                'steps': scenario['steps'],
                'likelihood': scenario['likelihood'],
                'impact': scenario['impact'],
                'risk_score': self._calculate_risk_score(scenario['likelihood'], scenario['impact']),
                'entry_points': [ep for ep in attack_surface.get('entry_points', []) 
                               if self._scenario_applies_to_entry_point(scenario, ep)]
            })
        
        return attack_paths
    
    async def _perform_risk_assessment(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Perform comprehensive risk assessment."""
        threats = results['threat_model']['threats']
        attack_paths = results['threat_model']['attack_paths']
        
        risk_assessment = {
            'overall_risk_score': 0,
            'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'top_risks': [],
            'business_impact': {},
            'risk_matrix': []
        }
        
        # Calculate overall risk
        total_risk = sum(threat['risk_score'] for threat in threats)
        risk_assessment['overall_risk_score'] = total_risk / len(threats) if threats else 0
        
        # Risk distribution
        for threat in threats:
            risk_level = self._get_risk_level(threat['risk_score'])
            risk_assessment['risk_distribution'][risk_level] += 1
        
        # Top risks
        top_risks = sorted(threats, key=lambda x: x['risk_score'], reverse=True)[:10]
        risk_assessment['top_risks'] = top_risks
        
        # Business impact assessment
        business_context = config.get('business_context', '')
        risk_assessment['business_impact'] = self._assess_business_impact(threats, business_context)
        
        # Risk matrix
        risk_assessment['risk_matrix'] = self._create_risk_matrix(threats)
        
        results['risk_assessment'] = risk_assessment
    
    async def _analyze_vulnerabilities(self, config: Dict[str, Any], results: Dict[str, Any], session: aiohttp.ClientSession):
        """Analyze potential vulnerabilities."""
        vulnerabilities = []
        
        # Web application vulnerabilities
        for webapp in results['attack_surface'].get('web_applications', []):
            web_vulns = await self._analyze_web_vulnerabilities(webapp, session)
            vulnerabilities.extend(web_vulns)
        
        # Network service vulnerabilities
        for service in results['attack_surface'].get('services', []):
            service_vulns = await self._analyze_service_vulnerabilities(service)
            vulnerabilities.extend(service_vulns)
        
        # Configuration vulnerabilities
        config_vulns = await self._analyze_configuration_vulnerabilities(results['attack_surface'])
        vulnerabilities.extend(config_vulns)
        
        results['vulnerabilities'] = vulnerabilities
    
    async def _analyze_compliance(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Analyze compliance with security frameworks."""
        frameworks = config.get('compliance_frameworks', [])
        compliance_gaps = {}
        
        for framework in frameworks:
            gaps = await self._check_compliance_framework(framework, results)
            compliance_gaps[framework] = gaps
        
        results['compliance_gaps'] = compliance_gaps
    
    async def _generate_recommendations(self, config: Dict[str, Any], results: Dict[str, Any]):
        """Generate security recommendations."""
        recommendations = []
        
        # High-risk threat mitigations
        for threat in results['threat_model']['threats']:
            if threat['risk_score'] >= 7.0:  # High or critical risk
                recommendations.extend(threat['mitigation_strategies'])
        
        # Vulnerability-based recommendations
        for vuln in results['vulnerabilities']:
            if vuln['severity'] in ['critical', 'high']:
                recommendations.append({
                    'category': 'Vulnerability Management',
                    'priority': vuln['severity'],
                    'recommendation': f"Address {vuln['type']}: {vuln['description']}",
                    'effort': vuln.get('remediation_effort', 'medium')
                })
        
        # Compliance recommendations
        for framework, gaps in results['compliance_gaps'].items():
            for gap in gaps:
                recommendations.append({
                    'category': f'{framework} Compliance',
                    'priority': gap['severity'],
                    'recommendation': gap['recommendation'],
                    'effort': gap.get('effort', 'medium')
                })
        
        # Remove duplicates and prioritize
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            rec_key = f"{rec['category']}:{rec['recommendation']}"
            if rec_key not in seen:
                seen.add(rec_key)
                unique_recommendations.append(rec)
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        unique_recommendations.sort(key=lambda x: priority_order.get(x['priority'], 5))
        
        results['recommendations'] = unique_recommendations[:20]  # Top 20 recommendations
    
    async def _generate_executive_summary(self, results: Dict[str, Any]):
        """Generate executive summary."""
        risk_assessment = results['risk_assessment']
        
        executive_summary = {
            'overall_risk_level': self._get_risk_level(risk_assessment['overall_risk_score']),
            'critical_findings': len([t for t in results['threat_model']['threats'] if t['risk_score'] >= 9.0]),
            'high_risk_findings': len([t for t in results['threat_model']['threats'] if 7.0 <= t['risk_score'] < 9.0]),
            'key_vulnerabilities': [v for v in results['vulnerabilities'] if v['severity'] in ['critical', 'high']][:5],
            'top_recommendations': results['recommendations'][:5],
            'attack_surface_summary': {
                'network_assets': len(results['attack_surface'].get('network_assets', [])),
                'web_applications': len(results['attack_surface'].get('web_applications', [])),
                'services': len(results['attack_surface'].get('services', [])),
                'entry_points': len(results['attack_surface'].get('entry_points', []))
            },
            'business_impact_summary': self._summarize_business_impact(results)
        }
        
        results['executive_summary'] = executive_summary
    
    # Helper methods
    def _reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return 'Unknown'
    
    def _detect_web_technologies(self, headers: Dict[str, str], html: str) -> List[str]:
        """Detect web technologies from headers and HTML."""
        technologies = []
        
        # Server header
        server = headers.get('Server', '')
        if server:
            technologies.append(server)
        
        # Powered-by header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(powered_by)
        
        # HTML-based detection
        if 'wp-content' in html:
            technologies.append('WordPress')
        if 'drupal' in html.lower():
            technologies.append('Drupal')
        
        return technologies
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP security headers."""
        security_headers = {
            'strict-transport-security': headers.get('Strict-Transport-Security'),
            'content-security-policy': headers.get('Content-Security-Policy'),
            'x-frame-options': headers.get('X-Frame-Options'),
            'x-content-type-options': headers.get('X-Content-Type-Options'),
            'x-xss-protection': headers.get('X-XSS-Protection'),
            'referrer-policy': headers.get('Referrer-Policy')
        }
        
        return {k: v for k, v in security_headers.items() if v is not None}
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port number."""
        port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 6379: 'redis'
        }
        return port_services.get(port, 'unknown')
    
    async def _grab_banner(self, host: str, port: int) -> str:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return ''
    
    def _extract_version(self, banner: str) -> str:
        """Extract version from banner."""
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
        return version_match.group(1) if version_match else 'Unknown'
    
    def _detect_frameworks(self, html: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect web frameworks."""
        frameworks = []
        
        # React
        if 'react' in html.lower() or 'reactjs' in html.lower():
            frameworks.append({
                'name': 'React',
                'category': 'JavaScript Framework',
                'confidence': 'medium'
            })
        
        # Angular
        if 'angular' in html.lower() or 'ng-' in html:
            frameworks.append({
                'name': 'Angular',
                'category': 'JavaScript Framework',
                'confidence': 'medium'
            })
        
        # Vue.js
        if 'vue' in html.lower() or 'v-' in html:
            frameworks.append({
                'name': 'Vue.js',
                'category': 'JavaScript Framework',
                'confidence': 'medium'
            })
        
        return frameworks
    
    def _detect_cms(self, html: str) -> Optional[Dict[str, Any]]:
        """Detect Content Management System."""
        if 'wp-content' in html or 'wp-includes' in html:
            return {
                'name': 'WordPress',
                'category': 'CMS',
                'confidence': 'high'
            }
        elif 'drupal' in html.lower():
            return {
                'name': 'Drupal',
                'category': 'CMS',
                'confidence': 'medium'
            }
        elif 'joomla' in html.lower():
            return {
                'name': 'Joomla',
                'category': 'CMS',
                'confidence': 'medium'
            }
        
        return None
    
    def _assess_service_risk(self, service: Dict[str, Any]) -> str:
        """Assess risk level of a service."""
        risky_services = ['telnet', 'ftp', 'ssh', 'rdp']
        if service['service'] in risky_services:
            return 'high'
        elif service['port'] < 1024:  # System ports
            return 'medium'
        else:
            return 'low'
    
    def _identify_assets(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify assets from attack surface."""
        assets = []
        
        # Network assets
        for asset in attack_surface.get('network_assets', []):
            assets.append({
                'type': 'network',
                'identifier': asset['ip'],
                'criticality': 'medium',
                'data_classification': 'unknown'
            })
        
        # Web applications
        for webapp in attack_surface.get('web_applications', []):
            assets.append({
                'type': 'web_application',
                'identifier': webapp['url'],
                'criticality': 'high',
                'data_classification': 'public'
            })
        
        return assets
    
    def _identify_trust_boundaries(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify trust boundaries."""
        boundaries = []
        
        # Internet to DMZ
        if attack_surface.get('web_applications'):
            boundaries.append({
                'name': 'Internet to DMZ',
                'description': 'External users accessing web applications',
                'trust_level_from': 'untrusted',
                'trust_level_to': 'limited'
            })
        
        # DMZ to Internal Network
        boundaries.append({
            'name': 'DMZ to Internal Network',
            'description': 'Web servers accessing internal resources',
            'trust_level_from': 'limited',
            'trust_level_to': 'trusted'
        })
        
        return boundaries
    
    def _assess_threat_likelihood(self, category: str, entry_point: Dict[str, Any], threat_actors: List[str]) -> str:
        """Assess likelihood of a threat."""
        # Simplified likelihood assessment
        if 'script_kiddie' in threat_actors and entry_point['type'] == 'web':
            return 'high'
        elif 'cybercriminal' in threat_actors:
            return 'medium'
        elif 'nation_state' in threat_actors:
            return 'low'
        else:
            return 'medium'
    
    def _assess_threat_impact(self, category: str, entry_point: Dict[str, Any]) -> str:
        """Assess impact of a threat."""
        impact_mapping = {
            'Information Disclosure': 'high',
            'Tampering': 'high',
            'Denial of Service': 'medium',
            'Spoofing': 'medium',
            'Repudiation': 'low',
            'Elevation of Privilege': 'critical'
        }
        return impact_mapping.get(category, 'medium')
    
    def _get_mitigation_strategies(self, category: str, entry_point: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get mitigation strategies for threat category."""
        strategies = {
            'Spoofing': [
                {'strategy': 'Implement strong authentication', 'priority': 'high', 'effort': 'medium'},
                {'strategy': 'Use multi-factor authentication', 'priority': 'high', 'effort': 'low'}
            ],
            'Tampering': [
                {'strategy': 'Implement input validation', 'priority': 'high', 'effort': 'medium'},
                {'strategy': 'Use integrity checks', 'priority': 'medium', 'effort': 'low'}
            ],
            'Information Disclosure': [
                {'strategy': 'Encrypt sensitive data', 'priority': 'critical', 'effort': 'medium'},
                {'strategy': 'Implement access controls', 'priority': 'high', 'effort': 'medium'}
            ],
            'Denial of Service': [
                {'strategy': 'Implement rate limiting', 'priority': 'medium', 'effort': 'low'},
                {'strategy': 'Use load balancing', 'priority': 'medium', 'effort': 'high'}
            ],
            'Elevation of Privilege': [
                {'strategy': 'Implement least privilege principle', 'priority': 'critical', 'effort': 'high'},
                {'strategy': 'Regular privilege audits', 'priority': 'high', 'effort': 'medium'}
            ]
        }
        return strategies.get(category, [])
    
    def _calculate_risk_score(self, likelihood: str, impact: str) -> float:
        """Calculate risk score based on likelihood and impact."""
        likelihood_scores = {'low': 1, 'medium': 3, 'high': 5}
        impact_scores = {'low': 1, 'medium': 3, 'high': 5, 'critical': 7}
        
        likelihood_score = likelihood_scores.get(likelihood, 3)
        impact_score = impact_scores.get(impact, 3)
        
        return (likelihood_score * impact_score) / 5  # Normalize to 0-7 scale
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 6:
            return 'critical'
        elif score >= 4:
            return 'high'
        elif score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _scenario_applies_to_entry_point(self, scenario: Dict[str, Any], entry_point: Dict[str, Any]) -> bool:
        """Check if attack scenario applies to entry point."""
        scenario_mappings = {
            'Web Application Compromise': ['web'],
            'Network Infiltration': ['network', 'service'],
            'Social Engineering Attack': ['web', 'network', 'service']
        }
        return entry_point['type'] in scenario_mappings.get(scenario['name'], [])
    
    def _assess_business_impact(self, threats: List[Dict[str, Any]], business_context: str) -> Dict[str, Any]:
        """Assess business impact of threats."""
        return {
            'financial_impact': 'medium',
            'operational_impact': 'high',
            'reputational_impact': 'medium',
            'regulatory_impact': 'low',
            'context': business_context
        }
    
    def _create_risk_matrix(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create risk matrix visualization data."""
        matrix = []
        for threat in threats:
            matrix.append({
                'threat': threat['description'],
                'likelihood': threat['likelihood'],
                'impact': threat['impact'],
                'risk_score': threat['risk_score'],
                'risk_level': self._get_risk_level(threat['risk_score'])
            })
        return matrix
    
    async def _analyze_web_vulnerabilities(self, webapp: Dict[str, Any], session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """Analyze web application vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing security headers
        security_headers = webapp.get('security_headers', {})
        missing_headers = []
        
        required_headers = [
            'strict-transport-security', 'content-security-policy',
            'x-frame-options', 'x-content-type-options'
        ]
        
        for header in required_headers:
            if header not in security_headers:
                missing_headers.append(header)
        
        if missing_headers:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'medium',
                'description': f'Missing headers: {", ".join(missing_headers)}',
                'target': webapp['url'],
                'remediation_effort': 'low'
            })
        
        # Check for HTTP instead of HTTPS
        if webapp['url'].startswith('http://'):
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'high',
                'description': 'Website not using HTTPS',
                'target': webapp['url'],
                'remediation_effort': 'medium'
            })
        
        return vulnerabilities
    
    async def _analyze_service_vulnerabilities(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze service vulnerabilities."""
        vulnerabilities = []
        
        # Check for risky services
        risky_services = {
            'telnet': {'severity': 'critical', 'reason': 'Unencrypted protocol'},
            'ftp': {'severity': 'high', 'reason': 'Potentially unencrypted'},
            'ssh': {'severity': 'medium', 'reason': 'Potential brute force target'}
        }
        
        if service['service'] in risky_services:
            risk_info = risky_services[service['service']]
            vulnerabilities.append({
                'type': 'Risky Service',
                'severity': risk_info['severity'],
                'description': f'{service["service"]} service: {risk_info["reason"]}',
                'target': f'Port {service["port"]}',
                'remediation_effort': 'medium'
            })
        
        return vulnerabilities
    
    async def _analyze_configuration_vulnerabilities(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze configuration vulnerabilities."""
        vulnerabilities = []
        
        # Check for too many open ports
        services = attack_surface.get('services', [])
        if len(services) > 10:
            vulnerabilities.append({
                'type': 'Excessive Open Ports',
                'severity': 'medium',
                'description': f'{len(services)} open ports detected',
                'target': 'Network configuration',
                'remediation_effort': 'high'
            })
        
        return vulnerabilities
    
    async def _check_compliance_framework(self, framework: str, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check compliance with security framework."""
        gaps = []
        
        if framework == 'PCI-DSS':
            # Check for HTTPS requirement
            web_apps = results['attack_surface'].get('web_applications', [])
            http_apps = [app for app in web_apps if app['url'].startswith('http://')]
            
            if http_apps:
                gaps.append({
                    'requirement': 'PCI-DSS 4.1 - Encrypt transmission of cardholder data',
                    'severity': 'high',
                    'recommendation': 'Implement HTTPS for all web applications',
                    'effort': 'medium'
                })
        
        elif framework == 'NIST':
            # Check for access controls
            gaps.append({
                'requirement': 'NIST CSF - Identity and Access Management',
                'severity': 'medium',
                'recommendation': 'Implement comprehensive access controls',
                'effort': 'high'
            })
        
        return gaps
    
    def _summarize_business_impact(self, results: Dict[str, Any]) -> str:
        """Summarize business impact."""
        critical_count = len([t for t in results['threat_model']['threats'] if t['risk_score'] >= 9.0])
        high_count = len([t for t in results['threat_model']['threats'] if 7.0 <= t['risk_score'] < 9.0])
        
        if critical_count > 0:
            return f"Critical business risk with {critical_count} critical threats identified"
        elif high_count > 5:
            return f"High business risk with {high_count} high-risk threats"
        else:
            return "Moderate business risk with manageable threat levels"
    
    def cleanup(self):
        """Clean up module resources."""
        pass


# Create module instance
module = ThreatModelingModule()
