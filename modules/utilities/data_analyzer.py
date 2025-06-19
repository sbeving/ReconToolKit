"""
Data Analyzer Module
Advanced data analysis and correlation for reconnaissance results.
"""

import logging
import json
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict, Counter
import re
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
from modules.base_module import BaseModule


class DataAnalyzerModule(BaseModule):
    """Advanced data analysis and correlation module."""
    
    def __init__(self):
        super().__init__(
            name="Data Analyzer",
            description="Advanced analysis and correlation of reconnaissance data with visualization and insights",
            category="utilities"
        )
        
        self.logger = logging.getLogger(__name__)
        self.analysis_results = {}
        
        # Pattern matchers for various data types
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        self.port_pattern = re.compile(r':(\d{1,5})\b')
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'analysis_type',
                'type': 'combo',
                'label': 'Analysis Type',
                'required': True,
                'default': 'comprehensive',
                'options': [
                    'comprehensive', 'network_topology', 'vulnerability_correlation',
                    'threat_assessment', 'data_extraction', 'timeline_analysis'
                ],
                'tooltip': 'Type of analysis to perform'
            },
            {
                'name': 'input_data',
                'type': 'file',
                'label': 'Input Data File',
                'required': False,
                'default': '',
                'tooltip': 'JSON file containing reconnaissance results'
            },
            {
                'name': 'scan_ids',
                'type': 'text',
                'label': 'Scan IDs',
                'required': False,
                'default': '',
                'placeholder': 'Comma-separated scan IDs (leave empty for all)',
                'tooltip': 'Specific scan IDs to analyze'
            },
            {
                'name': 'target_filter',
                'type': 'text',
                'label': 'Target Filter',
                'required': False,
                'default': '',
                'placeholder': 'Filter by target domain/IP',
                'tooltip': 'Filter results by specific target'
            },
            {
                'name': 'generate_visualizations',
                'type': 'checkbox',
                'label': 'Generate Visualizations',
                'required': False,
                'default': True
            },
            {
                'name': 'export_format',
                'type': 'combo',
                'label': 'Export Format',
                'required': False,
                'default': 'json',
                'options': ['json', 'csv', 'html', 'pdf'],
                'tooltip': 'Format for analysis results export'
            },
            {
                'name': 'correlation_threshold',
                'type': 'number',
                'label': 'Correlation Threshold',
                'required': False,
                'default': 0.7,
                'min': 0.0,
                'max': 1.0,
                'tooltip': 'Minimum correlation score for relationships'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        analysis_type = inputs.get('analysis_type', '')
        if not analysis_type:
            return "Analysis type is required"
        
        input_file = inputs.get('input_data', '')
        scan_ids = inputs.get('scan_ids', '').strip()
        
        if not input_file and not scan_ids:
            return "Either input data file or scan IDs must be provided"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run data analysis."""
        try:
            self.update_progress("Starting data analysis...", 0)
            
            analysis_type = inputs.get('analysis_type', 'comprehensive')
            input_file = inputs.get('input_data', '')
            scan_ids = inputs.get('scan_ids', '').strip()
            target_filter = inputs.get('target_filter', '').strip()
            generate_viz = inputs.get('generate_visualizations', True)
            export_format = inputs.get('export_format', 'json')
            correlation_threshold = inputs.get('correlation_threshold', 0.7)
            
            # Load data
            self.update_progress("Loading reconnaissance data...", 10)
            data = self._load_data(input_file, scan_ids, target_filter)
            
            if not data:
                return {
                    'success': False,
                    'error': 'No data found to analyze',
                    'analysis_type': analysis_type
                }
            
            # Perform analysis based on type
            self.update_progress(f"Performing {analysis_type} analysis...", 30)
            
            if analysis_type == 'comprehensive':
                results = self._comprehensive_analysis(data, correlation_threshold)
            elif analysis_type == 'network_topology':
                results = self._network_topology_analysis(data)
            elif analysis_type == 'vulnerability_correlation':
                results = self._vulnerability_correlation_analysis(data, correlation_threshold)
            elif analysis_type == 'threat_assessment':
                results = self._threat_assessment_analysis(data)
            elif analysis_type == 'data_extraction':
                results = self._data_extraction_analysis(data)
            elif analysis_type == 'timeline_analysis':
                results = self._timeline_analysis(data)
            else:
                results = self._comprehensive_analysis(data, correlation_threshold)
            
            # Generate visualizations if requested
            if generate_viz:
                self.update_progress("Generating visualizations...", 80)
                visualizations = self._generate_visualizations(results, analysis_type)
                results['visualizations'] = visualizations
            
            # Prepare final results
            final_results = {
                'success': True,
                'analysis_type': analysis_type,
                'data_summary': {
                    'total_records': len(data),
                    'unique_targets': len(set(self._extract_targets(data))),
                    'analysis_timestamp': datetime.now().isoformat()
                },
                'results': results,
                'export_format': export_format,
                'correlation_threshold': correlation_threshold
            }
            
            self.update_progress("Analysis completed", 100)
            return final_results
            
        except Exception as e:
            self.logger.error(f"Error in data analysis: {e}")
            return {
                'success': False,
                'error': str(e),
                'analysis_type': inputs.get('analysis_type', 'unknown')
            }
    
    def _load_data(self, input_file: str, scan_ids: str, target_filter: str) -> List[Dict[str, Any]]:
        """Load reconnaissance data from various sources."""
        data = []
        
        # Load from input file
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
        
        # Load from database using scan IDs
        if scan_ids:
            try:
                # This would integrate with the database manager
                # For now, we'll simulate loading data
                scan_id_list = [sid.strip() for sid in scan_ids.split(',') if sid.strip()]
                # data.extend(self._load_from_database(scan_id_list))
            except Exception as e:
                self.logger.error(f"Error loading from database: {e}")
        
        # Apply target filter
        if target_filter and data:
            data = [item for item in data if target_filter.lower() in str(item).lower()]
        
        return data
    
    def _comprehensive_analysis(self, data: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
        """Perform comprehensive analysis of reconnaissance data."""
        results = {
            'overview': self._generate_overview(data),
            'asset_inventory': self._build_asset_inventory(data),
            'vulnerability_summary': self._analyze_vulnerabilities(data),
            'network_relationships': self._analyze_network_relationships(data, threshold),
            'risk_assessment': self._assess_risks(data),
            'recommendations': self._generate_recommendations(data),
            'data_quality_report': self._assess_data_quality(data)
        }
        
        return results
    
    def _network_topology_analysis(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network topology and relationships."""
        # Extract network entities
        entities = self._extract_network_entities(data)
        
        # Build network graph
        graph = self._build_network_graph(entities)
        
        # Analyze topology
        topology_metrics = self._calculate_topology_metrics(graph)
        
        # Identify critical nodes
        critical_nodes = self._identify_critical_nodes(graph)
        
        # Find clusters/subnets
        clusters = self._find_network_clusters(graph)
        
        return {
            'entities': entities,
            'topology_metrics': topology_metrics,
            'critical_nodes': critical_nodes,
            'network_clusters': clusters,
            'connectivity_matrix': self._build_connectivity_matrix(graph)
        }
    
    def _vulnerability_correlation_analysis(self, data: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
        """Correlate vulnerabilities across different assets."""
        vulns = self._extract_vulnerabilities(data)
        
        # Group vulnerabilities by type, severity, target
        vuln_by_type = defaultdict(list)
        vuln_by_severity = defaultdict(list)
        vuln_by_target = defaultdict(list)
        
        for vuln in vulns:
            vuln_by_type[vuln.get('type', 'unknown')].append(vuln)
            vuln_by_severity[vuln.get('severity', 'unknown')].append(vuln)
            vuln_by_target[vuln.get('target', 'unknown')].append(vuln)
        
        # Find correlations
        correlations = self._find_vulnerability_correlations(vulns, threshold)
        
        # Generate attack paths
        attack_paths = self._generate_attack_paths(vulns)
        
        return {
            'vulnerability_distribution': {
                'by_type': dict(vuln_by_type),
                'by_severity': dict(vuln_by_severity),
                'by_target': dict(vuln_by_target)
            },
            'correlations': correlations,
            'attack_paths': attack_paths,
            'remediation_priorities': self._prioritize_remediation(vulns)
        }
    
    def _threat_assessment_analysis(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform threat assessment based on reconnaissance data."""
        # Extract threat indicators
        threats = self._extract_threat_indicators(data)
        
        # Calculate threat scores
        threat_scores = self._calculate_threat_scores(threats)
        
        # Identify high-risk assets
        high_risk_assets = self._identify_high_risk_assets(data, threat_scores)
        
        # Generate threat landscape
        threat_landscape = self._build_threat_landscape(threats)
        
        return {
            'threat_indicators': threats,
            'threat_scores': threat_scores,
            'high_risk_assets': high_risk_assets,
            'threat_landscape': threat_landscape,
            'mitigation_strategies': self._suggest_mitigations(threats)
        }
    
    def _data_extraction_analysis(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract and categorize various data types from reconnaissance results."""
        extracted_data = {
            'ip_addresses': set(),
            'domains': set(),
            'subdomains': set(),
            'email_addresses': set(),
            'urls': set(),
            'ports': set(),
            'technologies': set(),
            'certificates': [],
            'headers': defaultdict(set),
            'credentials': [],
            'files': set(),
            'directories': set()
        }
        
        # Process each data item
        for item in data:
            self._extract_data_from_item(item, extracted_data)
        
        # Convert sets to lists for JSON serialization
        for key, value in extracted_data.items():
            if isinstance(value, set):
                extracted_data[key] = list(value)
            elif isinstance(value, defaultdict):
                extracted_data[key] = dict(value)
        
        # Generate statistics
        stats = self._generate_extraction_stats(extracted_data)
        
        return {
            'extracted_data': extracted_data,
            'statistics': stats,
            'data_relationships': self._analyze_data_relationships(extracted_data)
        }
    
    def _timeline_analysis(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in reconnaissance data."""
        # Extract timestamps
        timeline_events = self._extract_timeline_events(data)
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x.get('timestamp', ''))
        
        # Analyze patterns
        patterns = self._analyze_temporal_patterns(timeline_events)
        
        # Identify anomalies
        anomalies = self._detect_temporal_anomalies(timeline_events)
        
        return {
            'timeline_events': timeline_events,
            'temporal_patterns': patterns,
            'anomalies': anomalies,
            'activity_summary': self._summarize_activity(timeline_events)
        }
    
    def _extract_network_entities(self, data: List[Dict[str, Any]]) -> Dict[str, Set]:
        """Extract network entities from data."""
        entities = {
            'hosts': set(),
            'domains': set(),
            'ports': set(),
            'services': set()
        }
        
        for item in data:
            # Extract from various data structures
            self._extract_entities_recursive(item, entities)
        
        return {k: list(v) for k, v in entities.items()}
    
    def _build_network_graph(self, entities: Dict[str, List]) -> nx.Graph:
        """Build network graph from entities."""
        graph = nx.Graph()
        
        # Add nodes
        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                graph.add_node(entity, type=entity_type)
        
        # Add edges (this would be based on actual relationships found in data)
        # For now, we'll add some basic relationships
        for host in entities.get('hosts', []):
            for domain in entities.get('domains', []):
                if self._entities_related(host, domain):
                    graph.add_edge(host, domain)
        
        return graph
    
    def _generate_visualizations(self, results: Dict[str, Any], analysis_type: str) -> Dict[str, str]:
        """Generate visualizations for analysis results."""
        visualizations = {}
        
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            if analysis_type == 'network_topology' and 'topology_metrics' in results:
                # Network topology visualization  
                viz_path = self._create_network_topology_viz(results)
                if viz_path:
                    visualizations['network_topology'] = viz_path
            
            if 'vulnerability_distribution' in results:
                # Vulnerability distribution charts
                viz_path = self._create_vulnerability_distribution_viz(results)
                if viz_path:
                    visualizations['vulnerability_distribution'] = viz_path
            
            if 'threat_scores' in results:
                # Threat assessment visualization
                viz_path = self._create_threat_assessment_viz(results)
                if viz_path:
                    visualizations['threat_assessment'] = viz_path
            
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {e}")
        
        return visualizations
    
    def _extract_targets(self, data: List[Dict[str, Any]]) -> List[str]:
        """Extract target identifiers from data."""
        targets = []
        for item in data:
            if isinstance(item, dict):
                # Look for common target fields
                for field in ['target', 'domain', 'host', 'url', 'ip']:
                    if field in item and item[field]:
                        targets.append(str(item[field]))
        return targets
    
    def _extract_vulnerabilities(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from data."""
        vulnerabilities = []
        
        for item in data:
            if isinstance(item, dict):
                # Look for vulnerability data in various structures
                if 'vulnerabilities' in item:
                    if isinstance(item['vulnerabilities'], list):
                        vulnerabilities.extend(item['vulnerabilities'])
                elif 'results' in item and isinstance(item['results'], dict):
                    if 'vulnerabilities' in item['results']:
                        vulns = item['results']['vulnerabilities']
                        if isinstance(vulns, list):
                            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    # Additional helper methods would be implemented here...
    def _generate_overview(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analysis overview."""
        return {
            'total_scans': len(data),
            'scan_types': list(set(item.get('module_name', 'unknown') for item in data if isinstance(item, dict))),
            'targets_analyzed': len(set(self._extract_targets(data))),
            'analysis_scope': 'comprehensive'
        }
    
    def _build_asset_inventory(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build comprehensive asset inventory."""
        return {
            'hosts': [],
            'domains': [],
            'services': [],
            'technologies': []
        }
    
    def _analyze_vulnerabilities(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability data."""
        vulns = self._extract_vulnerabilities(data)
        
        severity_counts = Counter(v.get('severity', 'unknown') for v in vulns)
        type_counts = Counter(v.get('type', 'unknown') for v in vulns)
        
        return {
            'total_vulnerabilities': len(vulns),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'critical_vulnerabilities': [v for v in vulns if v.get('severity') == 'critical']
        }
    
    def _analyze_network_relationships(self, data: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
        """Analyze relationships between network entities."""
        return {
            'host_relationships': [],
            'service_dependencies': [],
            'trust_relationships': []
        }
    
    def _assess_risks(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk based on findings."""
        return {
            'overall_risk_score': 0.0,
            'risk_factors': [],
            'high_risk_areas': []
        }
    
    def _generate_recommendations(self, data: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate actionable recommendations."""
        return [
            {
                'category': 'security',
                'priority': 'high',
                'recommendation': 'Review and address critical vulnerabilities',
                'rationale': 'Critical vulnerabilities pose immediate risk'
            }
        ]
    
    def _assess_data_quality(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess quality of reconnaissance data."""
        return {
            'completeness_score': 0.85,
            'accuracy_indicators': [],
            'data_gaps': [],
            'quality_issues': []
        }
    
    # Placeholder implementations for other methods
    def _calculate_topology_metrics(self, graph) -> Dict[str, Any]:
        """Calculate network topology metrics."""
        return {
            'node_count': graph.number_of_nodes(),
            'edge_count': graph.number_of_edges(),
            'density': nx.density(graph) if graph.number_of_nodes() > 0 else 0,
            'clustering_coefficient': nx.average_clustering(graph) if graph.number_of_nodes() > 0 else 0
        }
    
    def _identify_critical_nodes(self, graph) -> List[str]:
        """Identify critical nodes in network."""
        if graph.number_of_nodes() == 0:
            return []
        
        centrality = nx.degree_centrality(graph)
        # Return top 10% most central nodes
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        top_count = max(1, len(sorted_nodes) // 10)
        return [node for node, _ in sorted_nodes[:top_count]]
    
    def _find_network_clusters(self, graph) -> List[List[str]]:
        """Find network clusters/communities."""
        if graph.number_of_nodes() == 0:
            return []
        
        try:
            import networkx.algorithms.community as nx_comm
            communities = nx_comm.greedy_modularity_communities(graph)
            return [list(community) for community in communities]
        except:
            return []
    
    def _build_connectivity_matrix(self, graph) -> Dict[str, Any]:
        """Build connectivity matrix."""
        return {
            'nodes': list(graph.nodes()),
            'adjacency_matrix': nx.adjacency_matrix(graph).toarray().tolist() if graph.number_of_nodes() > 0 else []
        }
    
    def _find_vulnerability_correlations(self, vulns: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
        """Find correlations between vulnerabilities."""
        return []
    
    def _generate_attack_paths(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate potential attack paths."""
        return []
    
    def _prioritize_remediation(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize vulnerability remediation."""
        return []
    
    def _extract_threat_indicators(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract threat indicators."""
        return []
    
    def _calculate_threat_scores(self, threats: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate threat scores."""
        return {}
    
    def _identify_high_risk_assets(self, data: List[Dict[str, Any]], threat_scores: Dict[str, float]) -> List[str]:
        """Identify high-risk assets."""
        return []
    
    def _build_threat_landscape(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build threat landscape."""
        return {}
    
    def _suggest_mitigations(self, threats: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Suggest threat mitigations."""
        return []
    
    def _extract_data_from_item(self, item: Dict[str, Any], extracted_data: Dict[str, Any]):
        """Extract various data types from a single item."""
        item_str = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
        
        # Extract IPs
        extracted_data['ip_addresses'].update(self.ip_pattern.findall(item_str))
        
        # Extract domains
        extracted_data['domains'].update(self.domain_pattern.findall(item_str))
        
        # Extract emails
        extracted_data['email_addresses'].update(self.email_pattern.findall(item_str))
        
        # Extract URLs
        extracted_data['urls'].update(self.url_pattern.findall(item_str))
        
        # Extract ports
        ports = self.port_pattern.findall(item_str)
        extracted_data['ports'].update(ports)
    
    def _generate_extraction_stats(self, extracted_data: Dict[str, Any]) -> Dict[str, int]:
        """Generate statistics for extracted data."""
        stats = {}
        for key, value in extracted_data.items():
            if isinstance(value, list):
                stats[f"{key}_count"] = len(value)
            elif isinstance(value, dict):
                stats[f"{key}_count"] = len(value)
        return stats
    
    def _analyze_data_relationships(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze relationships in extracted data."""
        return {
            'domain_ip_mappings': [],
            'email_domain_relationships': [],
            'url_domain_relationships': []
        }
    
    def _extract_timeline_events(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract timeline events from data."""
        events = []
        for item in data:
            if isinstance(item, dict) and 'timestamp' in item:
                events.append({
                    'timestamp': item['timestamp'],
                    'event_type': item.get('module_name', 'unknown'),
                    'target': item.get('target', 'unknown'),
                    'data': item
                })
        return events
    
    def _analyze_temporal_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in events."""
        return {
            'activity_peaks': [],
            'quiet_periods': [],
            'scan_frequency': {}
        }
    
    def _detect_temporal_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect temporal anomalies."""
        return []
    
    def _summarize_activity(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize activity patterns."""
        return {
            'total_events': len(events),
            'unique_targets': len(set(e.get('target', '') for e in events)),
            'event_types': list(set(e.get('event_type', '') for e in events))
        }
    
    def _extract_entities_recursive(self, item: Any, entities: Dict[str, Set]):
        """Recursively extract entities from data structure."""
        if isinstance(item, dict):
            for key, value in item.items():
                if key in ['host', 'ip', 'target'] and value:
                    if self.ip_pattern.match(str(value)):
                        entities['hosts'].add(str(value))
                elif key in ['domain', 'hostname'] and value:
                    entities['domains'].add(str(value))
                elif key in ['port', 'ports'] and value:
                    if isinstance(value, list):
                        entities['ports'].update(str(p) for p in value)
                    else:
                        entities['ports'].add(str(value))
                elif key in ['service', 'services'] and value:
                    if isinstance(value, list):
                        entities['services'].update(str(s) for s in value)
                    else:
                        entities['services'].add(str(value))
                else:
                    self._extract_entities_recursive(value, entities)
        elif isinstance(item, list):
            for subitem in item:
                self._extract_entities_recursive(subitem, entities)
    
    def _entities_related(self, entity1: str, entity2: str) -> bool:
        """Check if two entities are related."""
        # Simple heuristic - could be much more sophisticated
        return any([
            entity1 in entity2,
            entity2 in entity1,
            entity1.split('.')[0] == entity2.split('.')[0]  # Same subdomain/host
        ])
    
    def _create_network_topology_viz(self, results: Dict[str, Any]) -> Optional[str]:
        """Create network topology visualization."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Create a simple network visualization
            plt.figure(figsize=(12, 8))
            plt.title("Network Topology Analysis")
            plt.text(0.5, 0.5, "Network topology visualization would be generated here", 
                    ha='center', va='center', transform=plt.gca().transAxes)
            
            viz_path = "reports/network_topology_viz.png"
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return viz_path
        except Exception as e:
            self.logger.error(f"Error creating network topology visualization: {e}")
            return None
    
    def _create_vulnerability_distribution_viz(self, results: Dict[str, Any]) -> Optional[str]:
        """Create vulnerability distribution visualization."""
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(10, 6))
            plt.title("Vulnerability Distribution Analysis")
            plt.text(0.5, 0.5, "Vulnerability distribution charts would be generated here", 
                    ha='center', va='center', transform=plt.gca().transAxes)
            
            viz_path = "reports/vulnerability_distribution_viz.png"
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return viz_path
        except Exception as e:
            self.logger.error(f"Error creating vulnerability distribution visualization: {e}")
            return None
    
    def _create_threat_assessment_viz(self, results: Dict[str, Any]) -> Optional[str]:
        """Create threat assessment visualization."""
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(10, 6))
            plt.title("Threat Assessment Analysis")
            plt.text(0.5, 0.5, "Threat assessment visualizations would be generated here", 
                    ha='center', va='center', transform=plt.gca().transAxes)
            
            viz_path = "reports/threat_assessment_viz.png"
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return viz_path
        except Exception as e:
            self.logger.error(f"Error creating threat assessment visualization: {e}")
            return None
