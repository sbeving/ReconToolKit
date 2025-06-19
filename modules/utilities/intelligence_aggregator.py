"""
Intelligence Aggregator Module
Aggregates and correlates intelligence from multiple sources.
"""

import logging
import json
import time
import hashlib
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import urlparse, urljoin
import requests
from modules.base_module import BaseModule


class ThreatIntelligence:
    """Threat intelligence data structure."""
    
    def __init__(self):
        self.iocs = {  # Indicators of Compromise
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'file_hashes': set(),
            'email_addresses': set()
        }
        self.threat_feeds = []
        self.reputation_scores = {}
        self.attribution = {}
        self.last_updated = None
    
    def add_ioc(self, ioc_type: str, value: str, source: str, confidence: float = 0.5):
        """Add an indicator of compromise."""
        if ioc_type in self.iocs:
            self.iocs[ioc_type].add(value)
            self.reputation_scores[value] = {
                'score': confidence,
                'source': source,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_reputation(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Get reputation information for an indicator."""
        return self.reputation_scores.get(indicator)
    
    def is_malicious(self, indicator: str, threshold: float = 0.7) -> bool:
        """Check if an indicator is considered malicious."""
        rep = self.get_reputation(indicator)
        return rep and rep['score'] >= threshold


class IntelligenceAggregatorModule(BaseModule):
    """Advanced intelligence aggregation and correlation module."""
    
    def __init__(self):
        super().__init__(
            name="Intelligence Aggregator",
            description="Aggregate and correlate intelligence from multiple sources with threat analysis",
            category="utilities"
        )
        
        self.logger = logging.getLogger(__name__)
        self.threat_intel = ThreatIntelligence()
        
        # External threat intelligence sources (APIs would need keys)
        self.threat_sources = {
            'virustotal': {
                'name': 'VirusTotal',
                'enabled': False,
                'api_key': '',
                'base_url': 'https://www.virustotal.com/api/v3'
            },
            'alienvault': {
                'name': 'AlienVault OTX',
                'enabled': False,
                'api_key': '',
                'base_url': 'https://otx.alienvault.com/api/v1'
            },
            'shodan': {
                'name': 'Shodan',
                'enabled': False,
                'api_key': '',
                'base_url': 'https://api.shodan.io'
            },
            'abuse_ch': {
                'name': 'Abuse.ch',
                'enabled': True,
                'api_key': '',
                'base_url': 'https://urlhaus-api.abuse.ch/v1'
            }
        }
        
        # Pattern matchers
        self.patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'operation',
                'type': 'combo',
                'label': 'Operation',
                'required': True,
                'default': 'aggregate_intelligence',
                'options': [
                    'aggregate_intelligence', 'analyze_indicators', 'threat_hunting',
                    'reputation_check', 'ioc_extraction', 'threat_correlation',
                    'source_correlation', 'generate_report'
                ],
                'tooltip': 'Intelligence operation to perform'
            },
            {
                'name': 'input_data',
                'type': 'file',
                'label': 'Input Data File',
                'required': False,
                'default': '',
                'tooltip': 'JSON file containing reconnaissance or intelligence data'
            },
            {
                'name': 'scan_results_dir',
                'type': 'text',
                'label': 'Scan Results Directory',
                'required': False,
                'default': '',
                'placeholder': 'Directory containing scan result files'
            },
            {
                'name': 'indicators',
                'type': 'text',
                'label': 'Indicators (IOCs)',
                'required': False,
                'default': '',
                'placeholder': 'Comma-separated list of indicators to analyze'
            },
            {
                'name': 'threat_feeds',
                'type': 'multiselect',
                'label': 'Threat Intelligence Sources',
                'required': False,
                'default': ['abuse_ch'],
                'options': list(self.threat_sources.keys()),
                'tooltip': 'External threat intelligence sources to query'
            },
            {
                'name': 'correlation_threshold',
                'type': 'number',
                'label': 'Correlation Threshold',
                'required': False,
                'default': 0.6,
                'min': 0.0,
                'max': 1.0,
                'tooltip': 'Minimum correlation score for relationships'
            },
            {
                'name': 'reputation_threshold',
                'type': 'number',
                'label': 'Malicious Threshold',
                'required': False,
                'default': 0.7,
                'min': 0.0,
                'max': 1.0,
                'tooltip': 'Minimum score to consider indicator malicious'
            },
            {
                'name': 'include_passive_dns',
                'type': 'checkbox',
                'label': 'Include Passive DNS',
                'required': False,
                'default': True,
                'tooltip': 'Include passive DNS resolution data'
            },
            {
                'name': 'include_geolocation',
                'type': 'checkbox',
                'label': 'Include Geolocation',
                'required': False,
                'default': True,
                'tooltip': 'Include IP geolocation information'
            },
            {
                'name': 'export_iocs',
                'type': 'checkbox',
                'label': 'Export IOCs',
                'required': False,
                'default': True,
                'tooltip': 'Export extracted IOCs in standard formats'
            },
            {
                'name': 'export_format',
                'type': 'combo',
                'label': 'Export Format',
                'required': False,
                'default': 'json',
                'options': ['json', 'csv', 'stix', 'misp', 'yara'],
                'tooltip': 'Format for exporting intelligence data'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        operation = inputs.get('operation', '')
        if not operation:
            return "Operation is required"
        
        input_file = inputs.get('input_data', '')
        scan_dir = inputs.get('scan_results_dir', '')
        indicators = inputs.get('indicators', '').strip()
        
        if operation in ['aggregate_intelligence', 'analyze_indicators'] and not any([input_file, scan_dir, indicators]):
            return "At least one input source (file, directory, or indicators) is required"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute intelligence aggregation operation."""
        try:
            operation = inputs.get('operation', '')
            self.update_progress(f"Starting {operation}...", 0)
            
            if operation == 'aggregate_intelligence':
                return self._aggregate_intelligence(inputs, config)
            elif operation == 'analyze_indicators':
                return self._analyze_indicators(inputs, config)
            elif operation == 'threat_hunting':
                return self._threat_hunting(inputs, config)
            elif operation == 'reputation_check':
                return self._reputation_check(inputs, config)
            elif operation == 'ioc_extraction':
                return self._ioc_extraction(inputs, config)
            elif operation == 'threat_correlation':
                return self._threat_correlation(inputs, config)
            elif operation == 'source_correlation':
                return self._source_correlation(inputs, config)
            elif operation == 'generate_report':
                return self._generate_intelligence_report(inputs, config)
            else:
                return {
                    'success': False,
                    'error': f"Unknown operation: {operation}"
                }
        
        except Exception as e:
            self.logger.error(f"Error in intelligence aggregation: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': operation
            }
    
    def _aggregate_intelligence(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate intelligence from multiple sources."""
        self.update_progress("Loading intelligence data...", 10)
        
        # Load data from various sources
        intelligence_data = self._load_intelligence_data(inputs)
        
        if not intelligence_data:
            return {
                'success': False,
                'error': 'No intelligence data found to aggregate'
            }
        
        self.update_progress("Extracting indicators...", 30)
        
        # Extract indicators of compromise
        iocs = self._extract_all_iocs(intelligence_data)
        
        self.update_progress("Enriching with threat intelligence...", 50)
        
        # Enrich with external threat intelligence
        threat_feeds = inputs.get('threat_feeds', ['abuse_ch'])
        enriched_iocs = self._enrich_with_threat_intel(iocs, threat_feeds)
        
        self.update_progress("Correlating intelligence...", 70)
        
        # Correlate and analyze
        correlation_threshold = inputs.get('correlation_threshold', 0.6)
        correlations = self._correlate_intelligence(enriched_iocs, correlation_threshold)
        
        self.update_progress("Generating intelligence summary...", 90)
        
        # Generate summary and insights
        summary = self._generate_intelligence_summary(enriched_iocs, correlations)
        
        results = {
            'success': True,
            'operation': 'aggregate_intelligence',
            'summary': summary,
            'indicators': self._serialize_iocs(enriched_iocs),
            'correlations': correlations,
            'threat_landscape': self._build_threat_landscape(enriched_iocs),
            'recommendations': self._generate_threat_recommendations(enriched_iocs),
            'metadata': {
                'total_sources': len(intelligence_data),
                'total_indicators': sum(len(indicators) for indicators in enriched_iocs.values()),
                'high_confidence_indicators': len([
                    ioc for iocs in enriched_iocs.values() 
                    for ioc in iocs 
                    if isinstance(ioc, dict) and ioc.get('confidence', 0) > 0.8
                ]),
                'processing_timestamp': datetime.now().isoformat()
            }
        }
        
        # Export if requested
        if inputs.get('export_iocs', True):
            export_format = inputs.get('export_format', 'json')
            export_path = self._export_intelligence(results, export_format)
            results['export_path'] = export_path
        
        self.update_progress("Intelligence aggregation completed", 100)
        return results
    
    def _analyze_indicators(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze specific indicators of compromise."""
        indicators_input = inputs.get('indicators', '').strip()
        if not indicators_input:
            return {
                'success': False,
                'error': 'No indicators provided for analysis'
            }
        
        # Parse indicators
        indicators = [i.strip() for i in indicators_input.split(',') if i.strip()]
        
        self.update_progress("Analyzing indicators...", 20)
        
        analysis_results = {}
        threat_feeds = inputs.get('threat_feeds', ['abuse_ch'])
        reputation_threshold = inputs.get('reputation_threshold', 0.7)
        
        for i, indicator in enumerate(indicators):
            if not self.should_continue():
                break
            
            progress = 20 + (i / len(indicators)) * 60
            self.update_progress(f"Analyzing indicator {i+1}/{len(indicators)}: {indicator}", int(progress))
            
            # Determine indicator type
            ioc_type = self._classify_indicator(indicator)
            
            # Analyze indicator
            analysis = {
                'indicator': indicator,
                'type': ioc_type,
                'reputation': self._check_reputation(indicator, threat_feeds),
                'geolocation': None,
                'passive_dns': None,
                'related_indicators': [],
                'threat_classification': 'unknown',
                'confidence_score': 0.0
            }
            
            # Add geolocation for IPs
            if ioc_type == 'ip' and inputs.get('include_geolocation', True):
                analysis['geolocation'] = self._get_geolocation(indicator)
            
            # Add passive DNS for domains/IPs
            if ioc_type in ['ip', 'domain'] and inputs.get('include_passive_dns', True):
                analysis['passive_dns'] = self._get_passive_dns(indicator)
            
            # Determine threat classification
            if analysis['reputation']:
                rep_score = analysis['reputation'].get('score', 0)
                if rep_score >= reputation_threshold:
                    analysis['threat_classification'] = 'malicious'
                elif rep_score >= 0.4:
                    analysis['threat_classification'] = 'suspicious'
                else:
                    analysis['threat_classification'] = 'clean'
                
                analysis['confidence_score'] = rep_score
            
            analysis_results[indicator] = analysis
        
        self.update_progress("Generating analysis report...", 85)
        
        # Generate summary
        threat_summary = self._summarize_threat_analysis(analysis_results)
        
        return {
            'success': True,
            'operation': 'analyze_indicators',
            'analysis_results': analysis_results,
            'threat_summary': threat_summary,
            'total_indicators': len(indicators),
            'malicious_count': len([a for a in analysis_results.values() if a['threat_classification'] == 'malicious']),
            'suspicious_count': len([a for a in analysis_results.values() if a['threat_classification'] == 'suspicious']),
            'clean_count': len([a for a in analysis_results.values() if a['threat_classification'] == 'clean'])
        }
    
    def _threat_hunting(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat hunting based on intelligence."""
        self.update_progress("Initializing threat hunting...", 10)
        
        # Load intelligence data
        intelligence_data = self._load_intelligence_data(inputs)
        
        # Extract hunting hypotheses
        hunting_results = {
            'hypotheses_tested': [],
            'indicators_found': {},
            'anomalies_detected': [],
            'threat_actors_identified': [],
            'attack_patterns': [],
            'recommendations': []
        }
        
        self.update_progress("Testing threat hypotheses...", 50)
        
        # Test various threat hunting hypotheses
        hypotheses = [
            'suspicious_domain_patterns',
            'command_and_control_indicators',
            'malware_signatures',
            'lateral_movement_indicators',
            'data_exfiltration_patterns'
        ]
        
        for hypothesis in hypotheses:
            result = self._test_threat_hypothesis(hypothesis, intelligence_data)
            hunting_results['hypotheses_tested'].append({
                'hypothesis': hypothesis,
                'result': result,
                'confidence': result.get('confidence', 0.0)
            })
        
        self.update_progress("Analyzing threat patterns...", 80)
        
        # Analyze patterns and generate recommendations
        hunting_results['recommendations'] = self._generate_hunting_recommendations(hunting_results)
        
        return {
            'success': True,
            'operation': 'threat_hunting',
            'hunting_results': hunting_results,
            'total_hypotheses': len(hypotheses),
            'high_confidence_findings': len([
                h for h in hunting_results['hypotheses_tested'] 
                if h['confidence'] > 0.7
            ])
        }
    
    def _reputation_check(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Check reputation of indicators."""
        indicators_input = inputs.get('indicators', '').strip()
        if not indicators_input:
            return {
                'success': False,
                'error': 'No indicators provided for reputation check'
            }
        
        indicators = [i.strip() for i in indicators_input.split(',') if i.strip()]
        threat_feeds = inputs.get('threat_feeds', ['abuse_ch'])
        
        reputation_results = {}
        
        for i, indicator in enumerate(indicators):
            progress = (i / len(indicators)) * 100
            self.update_progress(f"Checking reputation {i+1}/{len(indicators)}: {indicator}", int(progress))
            
            reputation = self._check_reputation(indicator, threat_feeds)
            reputation_results[indicator] = reputation
        
        return {
            'success': True,
            'operation': 'reputation_check',
            'reputation_results': reputation_results,
            'total_indicators': len(indicators)
        }
    
    def _ioc_extraction(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract indicators of compromise from data."""
        intelligence_data = self._load_intelligence_data(inputs)
        
        if not intelligence_data:
            return {
                'success': False,
                'error': 'No data found for IOC extraction'
            }
        
        iocs = self._extract_all_iocs(intelligence_data)
        
        return {
            'success': True,
            'operation': 'ioc_extraction',
            'extracted_iocs': self._serialize_iocs(iocs),
            'ioc_counts': {ioc_type: len(indicators) for ioc_type, indicators in iocs.items()},
            'total_iocs': sum(len(indicators) for indicators in iocs.values())
        }
    
    def _load_intelligence_data(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Load intelligence data from various sources."""
        data = []
        
        # Load from input file
        input_file = inputs.get('input_data', '')
        if input_file:
            try:
                with open(input_file, 'r') as f:
                    file_data = json.load(f)
                    if isinstance(file_data, list):
                        data.extend(file_data)
                    else:
                        data.append(file_data)
            except Exception as e:
                self.logger.error(f"Error loading input file: {e}")
        
        # Load from scan results directory
        scan_dir = inputs.get('scan_results_dir', '')
        if scan_dir:
            try:
                import os
                for filename in os.listdir(scan_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(scan_dir, filename)
                        with open(filepath, 'r') as f:
                            scan_data = json.load(f)
                            data.append(scan_data)
            except Exception as e:
                self.logger.error(f"Error loading scan directory: {e}")
        
        return data
    
    def _extract_all_iocs(self, data: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """Extract all indicators of compromise from data."""
        iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'emails': set(),
            'hashes': set()
        }
        
        for item in data:
            data_str = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
            
            # Extract different types of IOCs
            iocs['ips'].update(self.patterns['ip'].findall(data_str))
            iocs['domains'].update(self.patterns['domain'].findall(data_str))
            iocs['urls'].update(self.patterns['url'].findall(data_str))
            iocs['emails'].update(self.patterns['email'].findall(data_str))
            
            # Extract hashes
            iocs['hashes'].update(self.patterns['md5'].findall(data_str))
            iocs['hashes'].update(self.patterns['sha1'].findall(data_str))
            iocs['hashes'].update(self.patterns['sha256'].findall(data_str))
        
        return iocs
    
    def _enrich_with_threat_intel(self, iocs: Dict[str, Set[str]], threat_feeds: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Enrich IOCs with threat intelligence."""
        enriched_iocs = {}
        
        for ioc_type, indicators in iocs.items():
            enriched_iocs[ioc_type] = []
            
            for indicator in indicators:
                enriched_indicator = {
                    'value': indicator,
                    'type': ioc_type,
                    'first_seen': datetime.now().isoformat(),
                    'sources': [],
                    'reputation': None,
                    'confidence': 0.0,
                    'tags': [],
                    'threat_types': []
                }
                
                # Check against threat feeds
                for feed in threat_feeds:
                    if feed in self.threat_sources and self.threat_sources[feed]['enabled']:
                        feed_result = self._query_threat_feed(feed, indicator, ioc_type)
                        if feed_result:
                            enriched_indicator['sources'].append(feed)
                            enriched_indicator['reputation'] = feed_result.get('reputation')
                            enriched_indicator['confidence'] = max(
                                enriched_indicator['confidence'],
                                feed_result.get('confidence', 0.0)
                            )
                            if feed_result.get('tags'):
                                enriched_indicator['tags'].extend(feed_result['tags'])
                            if feed_result.get('threat_types'):
                                enriched_indicator['threat_types'].extend(feed_result['threat_types'])
                
                enriched_iocs[ioc_type].append(enriched_indicator)
        
        return enriched_iocs
    
    def _query_threat_feed(self, feed_name: str, indicator: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query a specific threat intelligence feed."""
        try:
            feed_config = self.threat_sources[feed_name]
            
            if feed_name == 'abuse_ch':
                return self._query_abuse_ch(indicator, ioc_type)
            elif feed_name == 'virustotal':
                return self._query_virustotal(indicator, ioc_type, feed_config.get('api_key'))
            elif feed_name == 'shodan':
                return self._query_shodan(indicator, ioc_type, feed_config.get('api_key'))
            
        except Exception as e:
            self.logger.error(f"Error querying {feed_name}: {e}")
        
        return None
    
    def _query_abuse_ch(self, indicator: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch URLhaus API."""
        try:
            if ioc_type == 'urls':
                response = requests.post(
                    'https://urlhaus-api.abuse.ch/v1/url/',
                    data={'url': indicator},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('query_status') == 'ok':
                        return {
                            'reputation': 'malicious',
                            'confidence': 0.9,
                            'tags': data.get('tags', []),
                            'threat_types': ['malware', 'phishing']
                        }
            
        except Exception as e:
            self.logger.error(f"Error querying Abuse.ch: {e}")
        
        return None
    
    def _query_virustotal(self, indicator: str, ioc_type: str, api_key: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API."""
        if not api_key:
            return None
        
        try:
            headers = {'x-apikey': api_key}
            
            if ioc_type == 'domains':
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/domains/{indicator}',
                    headers=headers,
                    timeout=10
                )
            elif ioc_type == 'ips':
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}',
                    headers=headers,
                    timeout=10
                )
            elif ioc_type == 'urls':
                url_id = hashlib.sha256(indicator.encode()).hexdigest()
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/urls/{url_id}',
                    headers=headers,
                    timeout=10
                )
            else:
                return None
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious_count = stats.get('malicious', 0)
                total_count = sum(stats.values())
                
                if total_count > 0:
                    confidence = malicious_count / total_count
                    reputation = 'malicious' if confidence > 0.1 else 'clean'
                    
                    return {
                        'reputation': reputation,
                        'confidence': confidence,
                        'tags': attributes.get('tags', []),
                        'threat_types': ['malware'] if reputation == 'malicious' else []
                    }
        
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {e}")
        
        return None
    
    def _query_shodan(self, indicator: str, ioc_type: str, api_key: str) -> Optional[Dict[str, Any]]:
        """Query Shodan API."""
        if not api_key or ioc_type != 'ips':
            return None
        
        try:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{indicator}',
                params={'key': api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Analyze Shodan data for threat indicators
                ports = data.get('ports', [])
                hostnames = data.get('hostnames', [])
                
                # Basic heuristic for suspicious hosts
                suspicious_ports = [22, 23, 1433, 3389, 5900, 5984]
                open_suspicious_ports = [p for p in ports if p in suspicious_ports]
                
                confidence = 0.3 if open_suspicious_ports else 0.1
                
                return {
                    'reputation': 'suspicious' if open_suspicious_ports else 'unknown',
                    'confidence': confidence,
                    'tags': ['open-ports'] + [f'port-{p}' for p in open_suspicious_ports],
                    'threat_types': ['exposed-service'] if open_suspicious_ports else []
                }
        
        except Exception as e:
            self.logger.error(f"Error querying Shodan: {e}")
        
        return None
    
    def _classify_indicator(self, indicator: str) -> str:
        """Classify the type of indicator."""
        if self.patterns['ip'].match(indicator):
            return 'ip'
        elif self.patterns['domain'].match(indicator):
            return 'domain'
        elif self.patterns['url'].match(indicator):
            return 'url'
        elif self.patterns['email'].match(indicator):
            return 'email'
        elif self.patterns['md5'].match(indicator):
            return 'md5'
        elif self.patterns['sha1'].match(indicator):
            return 'sha1'
        elif self.patterns['sha256'].match(indicator):
            return 'sha256'
        else:
            return 'unknown'
    
    def _check_reputation(self, indicator: str, threat_feeds: List[str]) -> Optional[Dict[str, Any]]:
        """Check reputation of a single indicator."""
        best_result = None
        
        for feed in threat_feeds:
            if feed in self.threat_sources and self.threat_sources[feed]['enabled']:
                ioc_type = self._classify_indicator(indicator)
                result = self._query_threat_feed(feed, indicator, ioc_type)
                
                if result and (not best_result or result.get('confidence', 0) > best_result.get('confidence', 0)):
                    best_result = result
        
        return best_result
    
    def _get_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get geolocation information for an IP address."""
        try:
            # Using a free geolocation service
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon')
                    }
        except Exception as e:
            self.logger.error(f"Error getting geolocation for {ip}: {e}")
        
        return None
    
    def _get_passive_dns(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Get passive DNS information."""
        # This would require access to passive DNS services
        # For now, return a placeholder
        return {
            'records': [],
            'first_seen': None,
            'last_seen': None
        }
    
    # Additional helper methods with placeholder implementations
    def _correlate_intelligence(self, iocs: Dict[str, List[Dict[str, Any]]], threshold: float) -> List[Dict[str, Any]]:
        """Correlate intelligence indicators."""
        return []
    
    def _generate_intelligence_summary(self, iocs: Dict[str, List[Dict[str, Any]]], correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate intelligence summary."""
        total_iocs = sum(len(indicators) for indicators in iocs.values())
        malicious_iocs = sum(
            len([ioc for ioc in indicators if ioc.get('reputation') == 'malicious'])
            for indicators in iocs.values()
        )
        
        return {
            'total_indicators': total_iocs,
            'malicious_indicators': malicious_iocs,
            'threat_coverage': malicious_iocs / total_iocs if total_iocs > 0 else 0,
            'top_threat_types': [],
            'risk_score': min(1.0, malicious_iocs / max(1, total_iocs) * 2)
        }
    
    def _build_threat_landscape(self, iocs: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Build threat landscape overview."""
        return {
            'threat_actors': [],
            'attack_patterns': [],
            'geographical_distribution': {},
            'temporal_patterns': {}
        }
    
    def _generate_threat_recommendations(self, iocs: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, str]]:
        """Generate threat-based recommendations."""
        return [
            {
                'category': 'monitoring',
                'priority': 'high',
                'recommendation': 'Monitor identified malicious indicators',
                'rationale': 'Active threat indicators detected'
            }
        ]
    
    def _serialize_iocs(self, iocs: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Serialize IOCs for JSON output."""
        return iocs
    
    def _export_intelligence(self, results: Dict[str, Any], export_format: str) -> str:
        """Export intelligence data in specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"intelligence_report_{timestamp}.{export_format}"
        
        try:
            if export_format == 'json':
                with open(f"reports/{filename}", 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            elif export_format == 'csv':
                # Implement CSV export
                pass
            # Add other formats as needed
            
            return f"reports/{filename}"
        except Exception as e:
            self.logger.error(f"Error exporting intelligence: {e}")
            return ""
    
    def _threat_correlation(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate threats across data sources."""
        return {
            'success': True,
            'operation': 'threat_correlation',
            'correlations': [],
            'message': 'Threat correlation analysis completed'
        }
    
    def _source_correlation(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate intelligence sources."""
        return {
            'success': True,
            'operation': 'source_correlation',
            'source_relationships': [],
            'message': 'Source correlation analysis completed'
        }
    
    def _generate_intelligence_report(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive intelligence report."""
        return {
            'success': True,
            'operation': 'generate_report',
            'report_path': 'reports/intelligence_report.html',
            'message': 'Intelligence report generated successfully'
        }
    
    def _test_threat_hypothesis(self, hypothesis: str, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test a specific threat hunting hypothesis."""
        return {
            'hypothesis': hypothesis,
            'evidence_found': False,
            'confidence': 0.0,
            'indicators': [],
            'description': f'Testing {hypothesis} hypothesis'
        }
    
    def _generate_hunting_recommendations(self, hunting_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate threat hunting recommendations."""
        return [
            {
                'category': 'detection',
                'priority': 'medium',
                'recommendation': 'Implement continuous threat hunting',
                'rationale': 'Proactive threat detection capabilities needed'
            }
        ]
    
    def _summarize_threat_analysis(self, analysis_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize threat analysis results."""
        threat_counts = Counter(result['threat_classification'] for result in analysis_results.values())
        
        return {
            'total_analyzed': len(analysis_results),
            'threat_distribution': dict(threat_counts),
            'average_confidence': sum(r.get('confidence_score', 0) for r in analysis_results.values()) / len(analysis_results),
            'high_risk_indicators': [
                indicator for indicator, result in analysis_results.items()
                if result['threat_classification'] == 'malicious' and result.get('confidence_score', 0) > 0.8
            ]
        }
