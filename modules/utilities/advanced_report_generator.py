"""
Advanced Report Generator Module
Generate comprehensive reports in multiple formats with visualizations.
"""

import logging
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import base64
from pathlib import Path
from modules.base_module import BaseModule


class AdvancedReportGeneratorModule(BaseModule):
    """Advanced report generation with multiple formats and visualizations."""
    
    def __init__(self):
        super().__init__(
            name="Advanced Report Generator",
            description="Generate comprehensive reconnaissance reports in multiple formats with charts and visualizations",
            category="utilities"
        )
        
        self.logger = logging.getLogger(__name__)
        self.report_templates = {
            'executive_summary': {
                'name': 'Executive Summary',
                'description': 'High-level summary for management',
                'sections': ['overview', 'key_findings', 'risk_assessment', 'recommendations']
            },
            'technical_detailed': {
                'name': 'Technical Detailed Report',
                'description': 'Comprehensive technical findings',
                'sections': ['methodology', 'detailed_findings', 'vulnerabilities', 'technical_recommendations', 'appendices']
            },
            'vulnerability_report': {
                'name': 'Vulnerability Assessment Report',
                'description': 'Focus on security vulnerabilities',
                'sections': ['vulnerability_summary', 'detailed_vulnerabilities', 'remediation_plan', 'risk_matrix']
            },
            'compliance_report': {
                'name': 'Compliance Report',
                'description': 'Compliance and regulatory assessment',
                'sections': ['compliance_overview', 'gaps_analysis', 'remediation_roadmap', 'controls_matrix']
            },
            'penetration_test': {
                'name': 'Penetration Test Report',
                'description': 'Penetration testing results',
                'sections': ['executive_summary', 'scope_methodology', 'findings', 'exploitation_details', 'recommendations']
            }
        }
        
        self.supported_formats = {
            'html': 'Interactive HTML Report',
            'pdf': 'PDF Document',
            'docx': 'Microsoft Word Document',
            'json': 'JSON Data Export',
            'csv': 'CSV Data Export',
            'xml': 'XML Data Export',
            'markdown': 'Markdown Document'
        }
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'operation',
                'type': 'combo',
                'label': 'Operation',
                'required': True,
                'default': 'generate_report',
                'options': [
                    'generate_report', 'merge_reports', 'convert_format',
                    'create_template', 'list_templates', 'analyze_data'
                ],
                'tooltip': 'Report generation operation'
            },
            {
                'name': 'input_data',
                'type': 'file',
                'label': 'Input Data File',
                'required': False,
                'default': '',
                'tooltip': 'JSON file containing scan results or data to report on'
            },
            {
                'name': 'scan_results_dir',
                'type': 'text',
                'label': 'Scan Results Directory',
                'required': False,
                'default': '',
                'placeholder': 'Directory containing multiple scan result files'
            },
            {
                'name': 'report_template',
                'type': 'combo',
                'label': 'Report Template',
                'required': False,
                'default': 'technical_detailed',
                'options': list(self.report_templates.keys()),
                'tooltip': 'Type of report to generate'
            },
            {
                'name': 'output_format',
                'type': 'combo',
                'label': 'Output Format',
                'required': False,
                'default': 'html',
                'options': list(self.supported_formats.keys()),
                'tooltip': 'Format for the generated report'
            },
            {
                'name': 'report_title',
                'type': 'text',
                'label': 'Report Title',
                'required': False,
                'default': '',
                'placeholder': 'Custom report title'
            },
            {
                'name': 'target_organization',
                'type': 'text',
                'label': 'Target Organization',
                'required': False,
                'default': '',
                'placeholder': 'Organization name for the report'
            },
            {
                'name': 'assessor_name',
                'type': 'text',
                'label': 'Assessor Name',
                'required': False,
                'default': '',
                'placeholder': 'Name of the person/team conducting assessment'
            },
            {
                'name': 'include_visualizations',
                'type': 'checkbox',
                'label': 'Include Visualizations',
                'required': False,
                'default': True,
                'tooltip': 'Include charts and graphs in the report'
            },
            {
                'name': 'include_raw_data',
                'type': 'checkbox',
                'label': 'Include Raw Data',
                'required': False,
                'default': False,
                'tooltip': 'Include raw scan data in appendix'
            },
            {
                'name': 'include_recommendations',
                'type': 'checkbox',
                'label': 'Include Recommendations',
                'required': False,
                'default': True,
                'tooltip': 'Include actionable recommendations'
            },
            {
                'name': 'severity_threshold',
                'type': 'combo',
                'label': 'Minimum Severity',
                'required': False,
                'default': 'low',
                'options': ['low', 'medium', 'high', 'critical'],
                'tooltip': 'Minimum severity level to include in report'
            },
            {
                'name': 'custom_sections',
                'type': 'text',
                'label': 'Custom Sections',
                'required': False,
                'default': '',
                'placeholder': 'Comma-separated list of custom sections to include',
                'tooltip': 'Additional sections to include in the report'
            },
            {
                'name': 'company_logo',
                'type': 'file',
                'label': 'Company Logo',
                'required': False,
                'default': '',
                'tooltip': 'Company logo image file for the report header'
            },
            {
                'name': 'confidentiality_level',
                'type': 'combo',
                'label': 'Confidentiality Level',
                'required': False,
                'default': 'confidential',
                'options': ['public', 'internal', 'confidential', 'restricted'],
                'tooltip': 'Classification level of the report'
            },
            {
                'name': 'auto_anonymize',
                'type': 'checkbox',
                'label': 'Auto Anonymize',
                'required': False,
                'default': False,
                'tooltip': 'Automatically anonymize sensitive data in the report'
            },
            {
                'name': 'generate_executive_summary',
                'type': 'checkbox',
                'label': 'Generate Executive Summary',
                'required': False,
                'default': True,
                'tooltip': 'Generate an executive summary section'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        operation = inputs.get('operation', '')
        if not operation:
            return "Operation is required"
        
        if operation in ['generate_report', 'analyze_data']:
            input_file = inputs.get('input_data', '')
            scan_dir = inputs.get('scan_results_dir', '')
            
            if not input_file and not scan_dir:
                return "Either input data file or scan results directory is required"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute report generation operation."""
        try:
            operation = inputs.get('operation', '')
            self.update_progress(f"Starting {operation}...", 0)
            
            if operation == 'generate_report':
                return self._generate_report(inputs, config)
            elif operation == 'merge_reports':
                return self._merge_reports(inputs, config)
            elif operation == 'convert_format':
                return self._convert_format(inputs, config)
            elif operation == 'create_template':
                return self._create_template(inputs, config)
            elif operation == 'list_templates':
                return self._list_templates()
            elif operation == 'analyze_data':
                return self._analyze_data(inputs, config)
            else:
                return {
                    'success': False,
                    'error': f"Unknown operation: {operation}"
                }
        
        except Exception as e:
            self.logger.error(f"Error in report generation: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': operation
            }
    
    def _generate_report(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive report."""
        self.update_progress("Loading data...", 10)
        
        # Load and process data
        data = self._load_report_data(inputs)
        if not data:
            return {
                'success': False,
                'error': 'No data found to generate report'
            }
        
        self.update_progress("Analyzing data...", 30)
        
        # Analyze the data
        analysis = self._analyze_scan_data(data, inputs)
        
        self.update_progress("Generating report content...", 50)
        
        # Generate report content
        report_template = inputs.get('report_template', 'technical_detailed')
        report_content = self._generate_report_content(data, analysis, inputs, report_template)
        
        self.update_progress("Creating visualizations...", 70)
        
        # Generate visualizations if requested
        visualizations = {}
        if inputs.get('include_visualizations', True):
            visualizations = self._generate_visualizations(analysis)
        
        self.update_progress("Formatting report...", 85)
        
        # Format the report
        output_format = inputs.get('output_format', 'html')
        formatted_report = self._format_report(report_content, visualizations, output_format, inputs)
        
        self.update_progress("Saving report...", 95)
        
        # Save the report
        report_path = self._save_report(formatted_report, output_format, inputs)
        
        self.update_progress("Report generation completed", 100)
        
        return {
            'success': True,
            'operation': 'generate_report',
            'report_path': report_path,
            'report_format': output_format,
            'report_template': report_template,
            'total_findings': analysis.get('total_findings', 0),
            'high_risk_findings': analysis.get('high_risk_findings', 0),
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'data_sources': len(data),
                'report_size': len(formatted_report) if isinstance(formatted_report, str) else 0
            }
        }
    
    def _load_report_data(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Load data from various sources for reporting."""
        data = []
        
        # Load from input file
        input_file = inputs.get('input_data', '')
        if input_file and os.path.exists(input_file):
            try:
                with open(input_file, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                    if isinstance(file_data, list):
                        data.extend(file_data)
                    else:
                        data.append(file_data)
            except Exception as e:
                self.logger.error(f"Error loading input file: {e}")
        
        # Load from scan results directory
        scan_dir = inputs.get('scan_results_dir', '')
        if scan_dir and os.path.exists(scan_dir):
            try:
                for filename in os.listdir(scan_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(scan_dir, filename)
                        with open(filepath, 'r', encoding='utf-8') as f:
                            scan_data = json.load(f)
                            data.append(scan_data)
            except Exception as e:
                self.logger.error(f"Error loading scan directory: {e}")
        
        return data
    
    def _analyze_scan_data(self, data: List[Dict[str, Any]], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan data to extract key metrics and findings."""
        analysis = {
            'total_scans': len(data),
            'scan_types': set(),
            'targets': set(),
            'findings': [],
            'vulnerabilities': [],
            'total_findings': 0,
            'findings_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'high_risk_findings': 0,
            'technologies_detected': set(),
            'services_discovered': set(),
            'open_ports': set(),
            'domains_found': set(),
            'ips_found': set(),
            'emails_found': set(),
            'timeline': [],
            'scan_coverage': {},
            'risk_score': 0.0
        }
        
        severity_threshold = inputs.get('severity_threshold', 'low')
        threshold_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_severity_level = threshold_levels.get(severity_threshold, 0)
        
        for scan_data in data:
            # Extract basic scan info
            if isinstance(scan_data, dict):
                scan_type = scan_data.get('module_name', scan_data.get('operation', 'unknown'))
                analysis['scan_types'].add(scan_type)
                
                # Extract target information
                target = scan_data.get('target', scan_data.get('target_url', ''))
                if target:
                    analysis['targets'].add(target)
                
                # Extract findings based on scan type
                self._extract_findings_from_scan(scan_data, analysis, min_severity_level)
                
                # Extract timeline information
                timestamp = scan_data.get('timestamp', scan_data.get('created_at', ''))
                if timestamp:
                    analysis['timeline'].append({
                        'timestamp': timestamp,
                        'scan_type': scan_type,
                        'target': target
                    })
        
        # Calculate overall metrics
        analysis['total_findings'] = len(analysis['findings'])
        analysis['high_risk_findings'] = sum(1 for f in analysis['findings'] if f.get('severity') in ['high', 'critical'])
        
        # Calculate risk score
        if analysis['total_findings'] > 0:
            severity_weights = {'low': 1, 'medium': 3, 'high': 7, 'critical': 10}
            weighted_score = sum(
                severity_weights.get(f.get('severity', 'low'), 1) 
                for f in analysis['findings']
            )
            analysis['risk_score'] = min(10.0, weighted_score / analysis['total_findings'])
        
        # Convert sets to lists for JSON serialization
        for key, value in analysis.items():
            if isinstance(value, set):
                analysis[key] = list(value)
        
        return analysis
    
    def _extract_findings_from_scan(self, scan_data: Dict[str, Any], analysis: Dict[str, Any], min_severity_level: int):
        """Extract findings from a single scan result."""
        severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        
        # Look for findings in various structures
        findings_sources = [
            scan_data.get('results', {}),
            scan_data.get('vulnerabilities', []),
            scan_data.get('findings', []),
            scan_data.get('issues', [])
        ]
        
        for source in findings_sources:
            if isinstance(source, list):
                for finding in source:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'low').lower()
                        if severity_levels.get(severity, 0) >= min_severity_level:
                            processed_finding = {
                                'title': finding.get('title', finding.get('type', 'Unknown Finding')),
                                'description': finding.get('description', ''),
                                'severity': severity,
                                'target': finding.get('target', finding.get('url', '')),
                                'source_scan': scan_data.get('module_name', 'unknown'),
                                'timestamp': scan_data.get('timestamp', ''),
                                'evidence': finding.get('evidence', ''),
                                'recommendation': finding.get('recommendation', '')
                            }
                            analysis['findings'].append(processed_finding)
                            analysis['findings_by_severity'][severity] += 1
            
            elif isinstance(source, dict):
                # Extract from nested structures
                if 'vulnerabilities' in source:
                    vulns = source['vulnerabilities']
                    if isinstance(vulns, list):
                        for vuln in vulns:
                            if isinstance(vuln, dict):
                                severity = vuln.get('severity', 'low').lower()
                                if severity_levels.get(severity, 0) >= min_severity_level:
                                    analysis['vulnerabilities'].append(vuln)
                
                # Extract other data types
                if 'technologies' in source:
                    techs = source['technologies']
                    if isinstance(techs, list):
                        analysis['technologies_detected'].update(techs)
                
                if 'open_ports' in source:
                    ports = source['open_ports']
                    if isinstance(ports, list):
                        analysis['open_ports'].update(map(str, ports))
                
                if 'domains' in source:
                    domains = source['domains']
                    if isinstance(domains, list):
                        analysis['domains_found'].update(domains)
    
    def _generate_report_content(self, data: List[Dict[str, Any]], analysis: Dict[str, Any], 
                                inputs: Dict[str, Any], template: str) -> Dict[str, Any]:
        """Generate structured report content based on template."""
        template_config = self.report_templates.get(template, self.report_templates['technical_detailed'])
        
        content = {
            'metadata': self._generate_metadata(inputs, analysis),
            'sections': {}
        }
        
        # Generate each section based on template
        for section in template_config['sections']:
            if section == 'overview':
                content['sections']['overview'] = self._generate_overview_section(analysis, inputs)
            elif section == 'key_findings':
                content['sections']['key_findings'] = self._generate_key_findings_section(analysis)
            elif section == 'risk_assessment':
                content['sections']['risk_assessment'] = self._generate_risk_assessment_section(analysis)
            elif section == 'recommendations':
                content['sections']['recommendations'] = self._generate_recommendations_section(analysis)
            elif section == 'methodology':
                content['sections']['methodology'] = self._generate_methodology_section(data)
            elif section == 'detailed_findings':
                content['sections']['detailed_findings'] = self._generate_detailed_findings_section(analysis)
            elif section == 'vulnerabilities':
                content['sections']['vulnerabilities'] = self._generate_vulnerabilities_section(analysis)
            elif section == 'technical_recommendations':
                content['sections']['technical_recommendations'] = self._generate_technical_recommendations_section(analysis)
            elif section == 'appendices':
                content['sections']['appendices'] = self._generate_appendices_section(data, inputs)
        
        # Add custom sections if specified
        custom_sections = inputs.get('custom_sections', '')
        if custom_sections:
            for section_name in custom_sections.split(','):
                section_name = section_name.strip()
                if section_name:
                    content['sections'][section_name] = self._generate_custom_section(section_name, analysis)
        
        return content
    
    def _generate_metadata(self, inputs: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, str]:
        """Generate report metadata."""
        return {
            'title': inputs.get('report_title', 'Reconnaissance Assessment Report'),
            'organization': inputs.get('target_organization', 'Target Organization'),
            'assessor': inputs.get('assessor_name', 'ReconToolKit'),
            'generated_date': datetime.now().strftime('%Y-%m-%d'),
            'generated_time': datetime.now().strftime('%H:%M:%S'),
            'confidentiality': inputs.get('confidentiality_level', 'confidential'),
            'version': '1.0',
            'total_pages': 'TBD',  # Will be updated during formatting
            'executive_summary': 'Yes' if inputs.get('generate_executive_summary', True) else 'No'
        }
    
    def _generate_overview_section(self, analysis: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overview section."""
        return {
            'assessment_scope': {
                'targets_assessed': len(analysis['targets']),
                'scan_types_used': analysis['scan_types'],
                'total_scans_performed': analysis['total_scans']
            },
            'key_statistics': {
                'total_findings': analysis['total_findings'],
                'high_risk_findings': analysis['high_risk_findings'],
                'technologies_detected': len(analysis['technologies_detected']),
                'services_discovered': len(analysis['services_discovered']),
                'domains_found': len(analysis['domains_found'])
            },
            'risk_summary': {
                'overall_risk_score': analysis['risk_score'],
                'risk_level': self._get_risk_level(analysis['risk_score']),
                'critical_findings': analysis['findings_by_severity']['critical'],
                'high_findings': analysis['findings_by_severity']['high']
            }
        }
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on score."""
        if risk_score >= 8:
            return 'Critical'
        elif risk_score >= 6:
            return 'High'
        elif risk_score >= 4:
            return 'Medium'
        elif risk_score >= 2:
            return 'Low'
        else:
            return 'Minimal'
    
    def _generate_key_findings_section(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate key findings section."""
        # Get top findings by severity
        high_severity_findings = [
            f for f in analysis['findings'] 
            if f.get('severity') in ['critical', 'high']
        ]
        
        return {
            'summary': f"Assessment identified {analysis['total_findings']} total findings, with {len(high_severity_findings)} requiring immediate attention.",
            'critical_findings': [
                f for f in analysis['findings'] 
                if f.get('severity') == 'critical'
            ][:5],  # Top 5 critical
            'high_priority_findings': [
                f for f in analysis['findings'] 
                if f.get('severity') == 'high'
            ][:5],  # Top 5 high
            'trending_issues': self._identify_trending_issues(analysis['findings'])
        }
    
    def _identify_trending_issues(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify trending security issues from findings."""
        trending = []
        
        # Count finding types
        finding_types = {}
        for finding in findings:
            finding_type = finding.get('title', '').lower()
            for keyword in ['xss', 'sql injection', 'csrf', 'authentication', 'authorization', 'encryption']:
                if keyword in finding_type:
                    finding_types[keyword] = finding_types.get(keyword, 0) + 1
        
        # Sort by frequency
        sorted_types = sorted(finding_types.items(), key=lambda x: x[1], reverse=True)
        trending = [f"{issue_type.title()} ({count} instances)" for issue_type, count in sorted_types[:3]]
        
        return trending
    
    def _generate_risk_assessment_section(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment section."""
        return {
            'risk_matrix': {
                'critical': analysis['findings_by_severity']['critical'],
                'high': analysis['findings_by_severity']['high'],
                'medium': analysis['findings_by_severity']['medium'],
                'low': analysis['findings_by_severity']['low']
            },
            'risk_factors': self._identify_risk_factors(analysis),
            'business_impact': self._assess_business_impact(analysis),
            'likelihood_assessment': self._assess_likelihood(analysis),
            'overall_risk_rating': self._get_risk_level(analysis['risk_score'])
        }
    
    def _identify_risk_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify key risk factors."""
        risk_factors = []
        
        if analysis['findings_by_severity']['critical'] > 0:
            risk_factors.append("Critical vulnerabilities present")
        
        if len(analysis['open_ports']) > 10:
            risk_factors.append("Large attack surface with many open ports")
        
        if 'WordPress' in analysis['technologies_detected'] or 'Drupal' in analysis['technologies_detected']:
            risk_factors.append("CMS platforms requiring regular updates")
        
        return risk_factors
    
    def _assess_business_impact(self, analysis: Dict[str, Any]) -> str:
        """Assess potential business impact."""
        if analysis['findings_by_severity']['critical'] > 0:
            return "High - Critical vulnerabilities could lead to complete system compromise"
        elif analysis['findings_by_severity']['high'] > 3:
            return "Medium-High - Multiple high-severity issues could impact business operations"
        elif analysis['total_findings'] > 10:
            return "Medium - Multiple security issues require attention"
        else:
            return "Low - Limited security concerns identified"
    
    def _assess_likelihood(self, analysis: Dict[str, Any]) -> str:
        """Assess likelihood of exploitation."""
        if analysis['findings_by_severity']['critical'] > 0:
            return "High - Critical vulnerabilities are easily exploitable"
        elif len(analysis['open_ports']) > 15:
            return "Medium-High - Large attack surface increases exposure"
        else:
            return "Medium - Standard security concerns"
    
    def _generate_recommendations_section(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate recommendations section."""
        recommendations = {
            'immediate_actions': [],
            'short_term_recommendations': [],
            'long_term_recommendations': [],
            'remediation_timeline': {}
        }
        
        # Generate recommendations based on findings
        if analysis['findings_by_severity']['critical'] > 0:
            recommendations['immediate_actions'].append(
                "Address all critical vulnerabilities immediately (within 24-48 hours)"
            )
        
        if analysis['findings_by_severity']['high'] > 0:
            recommendations['short_term_recommendations'].append(
                "Remediate high-severity findings within 1-2 weeks"
            )
        
        if len(analysis['open_ports']) > 10:
            recommendations['short_term_recommendations'].append(
                "Review and close unnecessary open ports"
            )
        
        # Long-term recommendations
        recommendations['long_term_recommendations'].extend([
            "Implement regular security assessments",
            "Establish vulnerability management program",
            "Enhance security monitoring and logging"
        ])
        
        return recommendations
    
    def _generate_visualizations(self, analysis: Dict[str, Any]) -> Dict[str, str]:
        """Generate visualizations for the report."""
        visualizations = {}
        
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            import matplotlib.pyplot as plt
            
            # Create reports directory if it doesn't exist
            os.makedirs('reports/visualizations', exist_ok=True)
            
            # Severity distribution pie chart
            severity_data = analysis['findings_by_severity']
            if sum(severity_data.values()) > 0:
                plt.figure(figsize=(8, 6))
                plt.pie(severity_data.values(), labels=severity_data.keys(), autopct='%1.1f%%')
                plt.title('Findings by Severity')
                plt.savefig('reports/visualizations/severity_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
                visualizations['severity_distribution'] = 'reports/visualizations/severity_distribution.png'
            
            # Risk score gauge (simplified as bar chart)
            plt.figure(figsize=(8, 4))
            risk_score = analysis['risk_score']
            colors = ['green', 'yellow', 'orange', 'red', 'darkred']
            risk_levels = ['Minimal', 'Low', 'Medium', 'High', 'Critical']
            
            bars = plt.bar(risk_levels, [2, 2, 2, 2, 2], color=['lightgray']*5)
            
            # Highlight current risk level
            if risk_score >= 8:
                bars[4].set_color('darkred')
            elif risk_score >= 6:
                bars[3].set_color('red')
            elif risk_score >= 4:
                bars[2].set_color('orange')
            elif risk_score >= 2:
                bars[1].set_color('yellow')
            else:
                bars[0].set_color('green')
            
            plt.title(f'Overall Risk Score: {risk_score:.1f}/10')
            plt.ylabel('Risk Level')
            plt.savefig('reports/visualizations/risk_score.png', dpi=300, bbox_inches='tight')
            plt.close()
            visualizations['risk_score'] = 'reports/visualizations/risk_score.png'
            
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {e}")
        
        return visualizations
    
    def _format_report(self, content: Dict[str, Any], visualizations: Dict[str, str], 
                      output_format: str, inputs: Dict[str, Any]) -> str:
        """Format the report in the specified format."""
        if output_format == 'html':
            return self._format_html_report(content, visualizations, inputs)
        elif output_format == 'json':
            return json.dumps(content, indent=2, default=str)
        elif output_format == 'markdown':
            return self._format_markdown_report(content, inputs)
        elif output_format == 'csv':
            return self._format_csv_report(content)
        else:
            # Default to JSON for unsupported formats
            return json.dumps(content, indent=2, default=str)
    
    def _format_html_report(self, content: Dict[str, Any], visualizations: Dict[str, str], 
                           inputs: Dict[str, Any]) -> str:
        """Format report as HTML."""
        metadata = content['metadata']
        sections = content['sections']
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{metadata['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }}
        .header {{ text-align: center; border-bottom: 3px solid #2196F3; padding-bottom: 20px; margin-bottom: 30px; }}
        .title {{ color: #2196F3; font-size: 2.5em; margin: 0; }}
        .subtitle {{ color: #666; font-size: 1.2em; margin: 10px 0; }}
        .metadata {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .section {{ margin: 30px 0; }}
        .section-title {{ color: #2196F3; font-size: 1.8em; border-bottom: 2px solid #2196F3; padding-bottom: 5px; }}
        .finding {{ background: #fff; border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #388e3c; }}
        .risk-score {{ font-size: 2em; font-weight: bold; text-align: center; padding: 20px; }}
        .risk-critical {{ color: #d32f2f; }}
        .risk-high {{ color: #f57c00; }}
        .risk-medium {{ color: #fbc02d; }}
        .risk-low {{ color: #388e3c; }}
        .visualization {{ text-align: center; margin: 20px 0; }}
        .recommendation {{ background: #e3f2fd; border-left: 4px solid #2196F3; padding: 10px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .footer {{ text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">{metadata['title']}</h1>
        <p class="subtitle">{metadata['organization']}</p>
        <p>Generated on {metadata['generated_date']} at {metadata['generated_time']}</p>
        <p><strong>Confidentiality:</strong> {metadata['confidentiality'].title()}</p>
    </div>
"""
        
        # Add sections
        for section_name, section_content in sections.items():
            html += f'<div class="section">\n<h2 class="section-title">{section_name.replace("_", " ").title()}</h2>\n'
            
            if section_name == 'overview':
                html += self._format_overview_html(section_content)
            elif section_name == 'key_findings':
                html += self._format_key_findings_html(section_content)
            elif section_name == 'risk_assessment':
                html += self._format_risk_assessment_html(section_content)
            elif section_name == 'detailed_findings':
                html += self._format_detailed_findings_html(section_content)
            else:
                html += f'<pre>{json.dumps(section_content, indent=2)}</pre>'
            
            html += '</div>\n'
        
        # Add visualizations
        if visualizations:
            html += '<div class="section">\n<h2 class="section-title">Visualizations</h2>\n'
            for viz_name, viz_path in visualizations.items():
                if os.path.exists(viz_path):
                    with open(viz_path, 'rb') as img_file:
                        img_data = base64.b64encode(img_file.read()).decode()
                    html += f'<div class="visualization">\n<h3>{viz_name.replace("_", " ").title()}</h3>\n'
                    html += f'<img src="data:image/png;base64,{img_data}" alt="{viz_name}" style="max-width: 100%; height: auto;">\n</div>\n'
            html += '</div>\n'
        
        html += f"""
    <div class="footer">
        <p>Report generated by ReconToolKit - Advanced Reconnaissance Platform</p>
        <p>Generated by: {metadata['assessor']}</p>
    </div>
</body>
</html>
"""
        
        return html
    
    def _format_overview_html(self, overview: Dict[str, Any]) -> str:
        """Format overview section as HTML."""
        html = '<div class="overview">\n'
        
        if 'assessment_scope' in overview:
            scope = overview['assessment_scope']
            html += f"""
<h3>Assessment Scope</h3>
<ul>
    <li>Targets Assessed: {scope.get('targets_assessed', 0)}</li>
    <li>Scan Types Used: {', '.join(scope.get('scan_types_used', []))}</li>
    <li>Total Scans Performed: {scope.get('total_scans_performed', 0)}</li>
</ul>
"""
        
        if 'key_statistics' in overview:
            stats = overview['key_statistics']
            html += f"""
<h3>Key Statistics</h3>
<ul>
    <li>Total Findings: {stats.get('total_findings', 0)}</li>
    <li>High Risk Findings: {stats.get('high_risk_findings', 0)}</li>
    <li>Technologies Detected: {stats.get('technologies_detected', 0)}</li>
    <li>Services Discovered: {stats.get('services_discovered', 0)}</li>
</ul>
"""
        
        if 'risk_summary' in overview:
            risk = overview['risk_summary']
            risk_class = self._get_risk_css_class(risk.get('overall_risk_score', 0))
            html += f"""
<h3>Risk Summary</h3>
<div class="risk-score {risk_class}">
    Overall Risk Score: {risk.get('overall_risk_score', 0):.1f}/10
    <br>
    <span style="font-size: 0.6em;">Risk Level: {risk.get('risk_level', 'Unknown')}</span>
</div>
"""
        
        html += '</div>\n'
        return html
    
    def _get_risk_css_class(self, risk_score: float) -> str:
        """Get CSS class for risk score."""
        if risk_score >= 8:
            return 'risk-critical'
        elif risk_score >= 6:
            return 'risk-high'
        elif risk_score >= 4:
            return 'risk-medium'
        else:
            return 'risk-low'
    
    def _format_key_findings_html(self, findings: Dict[str, Any]) -> str:
        """Format key findings section as HTML."""
        html = '<div class="key-findings">\n'
        
        if 'summary' in findings:
            html += f'<p><strong>Summary:</strong> {findings["summary"]}</p>\n'
        
        if 'critical_findings' in findings:
            html += '<h3>Critical Findings</h3>\n'
            for finding in findings['critical_findings']:
                html += f'<div class="finding critical">\n'
                html += f'<h4>{finding.get("title", "Unknown Finding")}</h4>\n'
                html += f'<p>{finding.get("description", "No description available")}</p>\n'
                html += f'<p><strong>Target:</strong> {finding.get("target", "Unknown")}</p>\n'
                html += '</div>\n'
        
        html += '</div>\n'
        return html
    
    def _format_risk_assessment_html(self, risk_assessment: Dict[str, Any]) -> str:
        """Format risk assessment section as HTML."""
        html = '<div class="risk-assessment">\n'
        
        if 'risk_matrix' in risk_assessment:
            matrix = risk_assessment['risk_matrix']
            html += """
<h3>Risk Matrix</h3>
<table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr class="critical"><td>Critical</td><td>{}</td></tr>
    <tr class="high"><td>High</td><td>{}</td></tr>
    <tr class="medium"><td>Medium</td><td>{}</td></tr>
    <tr class="low"><td>Low</td><td>{}</td></tr>
</table>
""".format(matrix.get('critical', 0), matrix.get('high', 0), matrix.get('medium', 0), matrix.get('low', 0))
        
        if 'business_impact' in risk_assessment:
            html += f'<h3>Business Impact</h3>\n<p>{risk_assessment["business_impact"]}</p>\n'
        
        html += '</div>\n'
        return html
    
    def _format_detailed_findings_html(self, detailed_findings: Dict[str, Any]) -> str:
        """Format detailed findings section as HTML."""
        # This would be implemented based on the structure of detailed_findings
        return '<p>Detailed findings section would be formatted here.</p>'
    
    def _format_markdown_report(self, content: Dict[str, Any], inputs: Dict[str, Any]) -> str:
        """Format report as Markdown."""
        metadata = content['metadata']
        sections = content['sections']
        
        markdown = f"""# {metadata['title']}

**Organization:** {metadata['organization']}  
**Generated:** {metadata['generated_date']} at {metadata['generated_time']}  
**Assessor:** {metadata['assessor']}  
**Confidentiality:** {metadata['confidentiality'].title()}

---

"""
        
        # Add sections
        for section_name, section_content in sections.items():
            markdown += f"## {section_name.replace('_', ' ').title()}\n\n"
            markdown += f"```json\n{json.dumps(section_content, indent=2)}\n```\n\n"
        
        markdown += "---\n\n*Report generated by ReconToolKit - Advanced Reconnaissance Platform*\n"
        
        return markdown
    
    def _format_csv_report(self, content: Dict[str, Any]) -> str:
        """Format report as CSV (findings only)."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Title', 'Severity', 'Target', 'Description', 'Source'])
        
        # Extract findings from content
        if 'sections' in content and 'detailed_findings' in content['sections']:
            # This would extract findings from the detailed_findings section
            pass
        
        return output.getvalue()
    
    def _save_report(self, formatted_report: str, output_format: str, inputs: Dict[str, Any]) -> str:
        """Save the formatted report to file."""
        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_title = inputs.get('report_title', 'reconnaissance_report')
        safe_title = "".join(c for c in report_title if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_title = safe_title.replace(' ', '_').lower()
        
        filename = f"reports/{safe_title}_{timestamp}.{output_format}"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(formatted_report)
            
            self.logger.info(f"Report saved to {filename}")
            return filename
        
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            return ""
    
    # Placeholder implementations for other operations and sections
    def _merge_reports(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple reports."""
        return {
            'success': True,
            'operation': 'merge_reports',
            'message': 'Report merging functionality would be implemented here'
        }
    
    def _convert_format(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Convert report format."""
        return {
            'success': True,
            'operation': 'convert_format',
            'message': 'Format conversion functionality would be implemented here'
        }
    
    def _create_template(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Create custom report template."""
        return {
            'success': True,
            'operation': 'create_template',
            'message': 'Template creation functionality would be implemented here'
        }
    
    def _list_templates(self) -> Dict[str, Any]:
        """List available report templates."""
        return {
            'success': True,
            'operation': 'list_templates',
            'templates': self.report_templates,
            'supported_formats': self.supported_formats
        }
    
    def _analyze_data(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data without generating full report."""
        data = self._load_report_data(inputs)
        analysis = self._analyze_scan_data(data, inputs)
        
        return {
            'success': True,
            'operation': 'analyze_data',
            'analysis': analysis
        }
    
    # Additional placeholder methods for generating specific sections
    def _generate_methodology_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate methodology section."""
        return {
            'assessment_approach': 'Automated reconnaissance using ReconToolKit',
            'tools_used': list(set(item.get('module_name', 'unknown') for item in data if isinstance(item, dict))),
            'scope_limitations': 'Assessment limited to publicly accessible information',
            'testing_standards': 'Based on OWASP and NIST guidelines'
        }
    
    def _generate_vulnerabilities_section(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vulnerabilities section."""
        return {
            'vulnerability_summary': analysis.get('vulnerabilities', []),
            'exploitation_difficulty': 'Varies by vulnerability type',
            'affected_systems': analysis.get('targets', [])
        }
    
    def _generate_technical_recommendations_section(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical recommendations section."""
        return {
            'immediate_technical_actions': [
                'Patch critical vulnerabilities',
                'Review security configurations',
                'Update vulnerable software components'
            ],
            'security_controls': [
                'Implement Web Application Firewall',
                'Enable security headers',
                'Configure proper access controls'
            ],
            'monitoring_recommendations': [
                'Deploy intrusion detection systems',
                'Implement log aggregation and analysis',
                'Set up vulnerability scanning schedules'
            ]
        }
    
    def _generate_appendices_section(self, data: List[Dict[str, Any]], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Generate appendices section."""
        appendices = {
            'scan_configurations': 'Detailed scan configurations would be listed here',
            'tool_versions': 'Tool version information would be included',
            'references': [
                'OWASP Top 10',
                'NIST Cybersecurity Framework',
                'CWE/SANS Top 25'
            ]
        }
        
        # Include raw data if requested
        if inputs.get('include_raw_data', False):
            appendices['raw_scan_data'] = data
        
        return appendices
    
    def _generate_custom_section(self, section_name: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a custom section."""
        return {
            'section_name': section_name,
            'content': f'Custom section "{section_name}" content would be generated based on analysis data',
            'generated_at': datetime.now().isoformat()
        }
