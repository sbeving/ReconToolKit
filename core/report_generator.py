"""
Advanced Report Generator
Generates comprehensive reports in multiple formats with visualizations.
"""

import logging
import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from jinja2 import Template
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors


class AdvancedReportGenerator:
    """Advanced report generator with multiple output formats and visualizations."""
    
    def __init__(self, output_dir: str = "reports"):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        self.ensure_output_dir()
        
        # Set up matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def ensure_output_dir(self):
        """Ensure output directory exists."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Create subdirectories
        for subdir in ['html', 'pdf', 'json', 'csv', 'images']:
            subdir_path = os.path.join(self.output_dir, subdir)
            if not os.path.exists(subdir_path):
                os.makedirs(subdir_path)

    def generate_comprehensive_report(self, scan_results: Dict[str, Any], 
                                    report_format: str = 'html') -> str:
        """Generate a comprehensive report from scan results."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"recontoolkit_report_{timestamp}"
        
        # Process and analyze results
        processed_data = self._process_scan_results(scan_results)
        
        # Generate visualizations
        charts = self._generate_visualizations(processed_data, report_name)
        
        if report_format.lower() == 'html':
            return self._generate_html_report(processed_data, charts, report_name)
        elif report_format.lower() == 'pdf':
            return self._generate_pdf_report(processed_data, charts, report_name)
        elif report_format.lower() == 'json':
            return self._generate_json_report(processed_data, report_name)
        elif report_format.lower() == 'csv':
            return self._generate_csv_report(processed_data, report_name)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")

    def _process_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and organize scan results for reporting."""
        
        processed = {
            'executive_summary': self._create_executive_summary(scan_results),
            'scan_metadata': self._extract_scan_metadata(scan_results),
            'findings': self._categorize_findings(scan_results),
            'statistics': self._calculate_statistics(scan_results),
            'recommendations': self._generate_recommendations(scan_results),
            'raw_data': scan_results
        }
        
        return processed

    def _create_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary from scan results."""
        
        summary = {
            'total_targets': 0,
            'total_findings': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'modules_executed': [],
            'scan_duration': 0,
            'key_findings': []
        }
        
        # Process each module's results
        for module_name, results in scan_results.items():
            if isinstance(results, dict):
                summary['modules_executed'].append(module_name)
                
                # Count findings by severity
                if 'vulnerabilities' in results:
                    for vuln in results['vulnerabilities']:
                        severity = vuln.get('severity', 'low').lower()
                        if severity == 'critical':
                            summary['critical_issues'] += 1
                        elif severity == 'high':
                            summary['high_issues'] += 1
                        elif severity == 'medium':
                            summary['medium_issues'] += 1
                        else:
                            summary['low_issues'] += 1
                
                # Extract key findings
                if 'summary' in results:
                    if results['summary'].get('total_vulnerabilities', 0) > 0:
                        summary['key_findings'].append(f"{module_name}: {results['summary']['total_vulnerabilities']} vulnerabilities found")
        
        summary['total_findings'] = (summary['critical_issues'] + summary['high_issues'] + 
                                   summary['medium_issues'] + summary['low_issues'])
        
        return summary

    def _extract_scan_metadata(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata about the scan."""
        
        metadata = {
            'scan_date': datetime.now().isoformat(),
            'tool_version': '1.0.0',
            'scan_type': 'Comprehensive Reconnaissance',
            'targets': [],
            'modules': list(scan_results.keys())
        }
        
        # Extract target information
        for module_name, results in scan_results.items():
            if isinstance(results, dict) and 'summary' in results:
                if 'target' in results['summary']:
                    target = results['summary']['target']
                    if target not in metadata['targets']:
                        metadata['targets'].append(target)
        
        return metadata

    def _categorize_findings(self, scan_results: Dict[str, Any]) -> Dict[str, List]:
        """Categorize findings by type and severity."""
        
        findings = {
            'vulnerabilities': [],
            'open_ports': [],
            'subdomains': [],
            'certificates': [],
            'emails': [],
            'technologies': []
        }
        
        for module_name, results in scan_results.items():
            if not isinstance(results, dict):
                continue
                
            # Vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    vuln['module'] = module_name
                    findings['vulnerabilities'].append(vuln)
            
            # Open ports
            if 'hosts' in results:
                for host in results['hosts']:
                    for port in host.get('open_ports', []):
                        port['host'] = host['ip']
                        port['module'] = module_name
                        findings['open_ports'].append(port)
            
            # Subdomains
            if 'subdomains' in results:
                for subdomain in results['subdomains']:
                    subdomain['module'] = module_name
                    findings['subdomains'].append(subdomain)
            
            # SSL certificates
            if 'certificate' in results:
                cert = results['certificate']
                cert['module'] = module_name
                findings['certificates'].append(cert)
        
        return findings

    def _calculate_statistics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate various statistics from scan results."""
        
        stats = {
            'vulnerability_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'port_distribution': {},
            'service_distribution': {},
            'module_execution_times': {},
            'top_vulnerabilities': [],
            'security_score': 0
        }
        
        total_vulns = 0
        
        for module_name, results in scan_results.items():
            if not isinstance(results, dict):
                continue
            
            # Vulnerability distribution
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'low').lower()
                    if severity in stats['vulnerability_distribution']:
                        stats['vulnerability_distribution'][severity] += 1
                        total_vulns += 1
            
            # Port distribution
            if 'hosts' in results:
                for host in results['hosts']:
                    for port in host.get('open_ports', []):
                        port_num = port['port']
                        stats['port_distribution'][port_num] = stats['port_distribution'].get(port_num, 0) + 1
                        
                        service = port.get('service', 'unknown')
                        stats['service_distribution'][service] = stats['service_distribution'].get(service, 0) + 1
            
            # Execution times
            if 'summary' in results and 'scan_time' in results['summary']:
                stats['module_execution_times'][module_name] = results['summary']['scan_time']
        
        # Calculate security score (100 - penalty for vulnerabilities)
        penalty = (stats['vulnerability_distribution']['critical'] * 25 + 
                  stats['vulnerability_distribution']['high'] * 15 + 
                  stats['vulnerability_distribution']['medium'] * 10 + 
                  stats['vulnerability_distribution']['low'] * 5)
        
        stats['security_score'] = max(0, 100 - penalty)
        
        return stats

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings."""
        
        recommendations = []
        
        for module_name, results in scan_results.items():
            if not isinstance(results, dict):
                continue
            
            if 'vulnerabilities' in results:
                critical_vulns = [v for v in results['vulnerabilities'] if v.get('severity') == 'critical']
                high_vulns = [v for v in results['vulnerabilities'] if v.get('severity') == 'high']
                
                if critical_vulns:
                    recommendations.append({
                        'priority': 'Critical',
                        'category': 'Vulnerability Management',
                        'title': f'Address Critical Vulnerabilities in {module_name}',
                        'description': f'Found {len(critical_vulns)} critical vulnerabilities that require immediate attention.',
                        'action': 'Patch vulnerable systems, implement security controls, and conduct security testing.'
                    })
                
                if high_vulns:
                    recommendations.append({
                        'priority': 'High',
                        'category': 'Vulnerability Management',
                        'title': f'Remediate High-Risk Issues in {module_name}',
                        'description': f'Found {len(high_vulns)} high-risk vulnerabilities.',
                        'action': 'Schedule patching and security updates within 30 days.'
                    })
        
        # Add general recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'category': 'Security Monitoring',
                'title': 'Implement Continuous Security Monitoring',
                'description': 'Regular security assessments help identify new vulnerabilities.',
                'action': 'Set up automated vulnerability scanning and monitoring tools.'
            },
            {
                'priority': 'Medium',
                'category': 'Security Training',
                'title': 'Conduct Security Awareness Training',
                'description': 'Human factor is often the weakest link in security.',
                'action': 'Provide regular security training to all personnel.'
            }
        ])
        
        return recommendations

    def _generate_visualizations(self, processed_data: Dict[str, Any], report_name: str) -> Dict[str, str]:
        """Generate visualizations and return file paths."""
        
        charts = {}
        images_dir = os.path.join(self.output_dir, 'images')
        
        # Vulnerability distribution pie chart
        if processed_data['statistics']['vulnerability_distribution']:
            vuln_dist = processed_data['statistics']['vulnerability_distribution']
            if sum(vuln_dist.values()) > 0:
                plt.figure(figsize=(10, 8))
                labels = [f"{k.title()} ({v})" for k, v in vuln_dist.items() if v > 0]
                sizes = [v for v in vuln_dist.values() if v > 0]
                colors = ['#ff4444', '#ff8800', '#ffaa00', '#44aa44'][:len(sizes)]
                
                plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                plt.title('Vulnerability Distribution by Severity', fontsize=16, fontweight='bold')
                plt.axis('equal')
                
                chart_path = os.path.join(images_dir, f'{report_name}_vuln_dist.png')
                plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                charts['vulnerability_distribution'] = chart_path
        
        # Port distribution bar chart
        if processed_data['statistics']['port_distribution']:
            port_dist = processed_data['statistics']['port_distribution']
            top_ports = dict(sorted(port_dist.items(), key=lambda x: x[1], reverse=True)[:10])
            
            if top_ports:
                plt.figure(figsize=(12, 6))
                ports = list(top_ports.keys())
                counts = list(top_ports.values())
                
                bars = plt.bar(range(len(ports)), counts, color='steelblue', alpha=0.7)
                plt.xlabel('Port Number', fontsize=12)
                plt.ylabel('Frequency', fontsize=12)
                plt.title('Top 10 Open Ports Distribution', fontsize=16, fontweight='bold')
                plt.xticks(range(len(ports)), ports, rotation=45)
                
                # Add value labels on bars
                for bar, count in zip(bars, counts):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                            str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                chart_path = os.path.join(images_dir, f'{report_name}_port_dist.png')
                plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                charts['port_distribution'] = chart_path
        
        # Security score gauge
        security_score = processed_data['statistics']['security_score']
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = security_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Score"},
            delta = {'reference': 80},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "gray"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        chart_path = os.path.join(images_dir, f'{report_name}_security_score.html')
        fig.write_html(chart_path)
        charts['security_score'] = chart_path
        
        return charts

    def _generate_html_report(self, processed_data: Dict[str, Any], 
                            charts: Dict[str, str], report_name: str) -> str:
        """Generate HTML report."""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconToolKit Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #2196F3; padding-bottom: 20px; margin-bottom: 30px; }
        .title { color: #2196F3; font-size: 2.5em; font-weight: bold; margin: 0; }
        .subtitle { color: #666; font-size: 1.2em; margin: 10px 0; }
        .section { margin: 30px 0; }
        .section-title { color: #333; font-size: 1.8em; font-weight: bold; border-bottom: 2px solid #2196F3; padding-bottom: 10px; margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; text-align: center; min-width: 120px; }
        .metric-value { font-size: 2em; font-weight: bold; display: block; }
        .metric-label { font-size: 0.9em; }
        .finding { background: #f8f9fa; border-left: 4px solid #28a745; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; height: auto; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .recommendation { background: #e3f2fd; border: 1px solid #2196F3; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .recommendation-title { font-weight: bold; color: #1976d2; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .table th { background-color: #2196F3; color: white; }
        .table tr:nth-child(even) { background-color: #f2f2f2; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">ReconToolKit</h1>
            <p class="subtitle">Comprehensive Security Assessment Report</p>
            <p>Generated on {{ scan_date }}</p>
        </div>

        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div style="text-align: center;">
                <div class="metric">
                    <span class="metric-value">{{ executive_summary.total_findings }}</span>
                    <span class="metric-label">Total Findings</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{{ executive_summary.critical_issues }}</span>
                    <span class="metric-label">Critical</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{{ executive_summary.high_issues }}</span>
                    <span class="metric-label">High</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{{ executive_summary.medium_issues }}</span>
                    <span class="metric-label">Medium</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{{ executive_summary.low_issues }}</span>
                    <span class="metric-label">Low</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{{ statistics.security_score }}%</span>
                    <span class="metric-label">Security Score</span>
                </div>
            </div>
        </div>

        {% if charts.vulnerability_distribution %}
        <div class="section">
            <h2 class="section-title">Vulnerability Analysis</h2>
            <div class="chart">
                <img src="{{ charts.vulnerability_distribution }}" alt="Vulnerability Distribution">
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2 class="section-title">Key Findings</h2>
            {% for finding in findings.vulnerabilities[:10] %}
            <div class="finding {{ finding.severity }}">
                <strong>{{ finding.type }}</strong> - {{ finding.severity|title }} Severity<br>
                <strong>URL:</strong> {{ finding.url }}<br>
                <strong>Description:</strong> {{ finding.description }}
            </div>
            {% endfor %}
        </div>

        {% if charts.port_distribution %}
        <div class="section">
            <h2 class="section-title">Network Analysis</h2>
            <div class="chart">
                <img src="{{ charts.port_distribution }}" alt="Port Distribution">
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2 class="section-title">Recommendations</h2>
            {% for rec in recommendations %}
            <div class="recommendation">
                <div class="recommendation-title">{{ rec.title }} ({{ rec.priority }})</div>
                <strong>Category:</strong> {{ rec.category }}<br>
                <strong>Description:</strong> {{ rec.description }}<br>
                <strong>Action:</strong> {{ rec.action }}
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>Report generated by ReconToolKit v1.0.0</p>
            <p>For questions or support, contact your security team</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            scan_date=processed_data['scan_metadata']['scan_date'],
            executive_summary=processed_data['executive_summary'],
            statistics=processed_data['statistics'],
            findings=processed_data['findings'],
            recommendations=processed_data['recommendations'],
            charts=charts
        )
        
        output_path = os.path.join(self.output_dir, 'html', f'{report_name}.html')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path

    def _generate_json_report(self, processed_data: Dict[str, Any], report_name: str) -> str:
        """Generate JSON report."""
        
        output_path = os.path.join(self.output_dir, 'json', f'{report_name}.json')
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, indent=2, default=str)
        
        return output_path

    def _generate_csv_report(self, processed_data: Dict[str, Any], report_name: str) -> str:
        """Generate CSV reports for tabular data."""
        
        csv_dir = os.path.join(self.output_dir, 'csv')
        
        # Vulnerabilities CSV
        if processed_data['findings']['vulnerabilities']:
            vulns_df = pd.DataFrame(processed_data['findings']['vulnerabilities'])
            vulns_path = os.path.join(csv_dir, f'{report_name}_vulnerabilities.csv')
            vulns_df.to_csv(vulns_path, index=False)
        
        # Open ports CSV
        if processed_data['findings']['open_ports']:
            ports_df = pd.DataFrame(processed_data['findings']['open_ports'])
            ports_path = os.path.join(csv_dir, f'{report_name}_open_ports.csv')
            ports_df.to_csv(ports_path, index=False)
        
        return csv_dir

    def _generate_pdf_report(self, processed_data: Dict[str, Any], 
                           charts: Dict[str, str], report_name: str) -> str:
        """Generate PDF report."""
        
        output_path = os.path.join(self.output_dir, 'pdf', f'{report_name}.pdf')
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2196F3'),
            alignment=1  # Center
        )
        story.append(Paragraph("ReconToolKit Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary = processed_data['executive_summary']
        summary_data = [
            ['Metric', 'Value'],
            ['Total Findings', str(summary['total_findings'])],
            ['Critical Issues', str(summary['critical_issues'])],
            ['High Issues', str(summary['high_issues'])],
            ['Medium Issues', str(summary['medium_issues'])],
            ['Low Issues', str(summary['low_issues'])],
            ['Security Score', f"{processed_data['statistics']['security_score']}%"]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2196F3')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Add charts if available
        if 'vulnerability_distribution' in charts:
            story.append(Paragraph("Vulnerability Distribution", styles['Heading2']))
            story.append(Image(charts['vulnerability_distribution'], width=400, height=300))
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Key Recommendations", styles['Heading2']))
        for i, rec in enumerate(processed_data['recommendations'][:5], 1):
            story.append(Paragraph(f"{i}. {rec['title']}", styles['Heading3']))
            story.append(Paragraph(f"Priority: {rec['priority']}", styles['Normal']))
            story.append(Paragraph(rec['description'], styles['Normal']))
            story.append(Spacer(1, 10))
        
        doc.build(story)
        return output_path
