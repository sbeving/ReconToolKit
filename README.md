# ReconToolKit: Advanced OSINT & Reconnaissance Platform

![ReconToolKit Logo](https://img.shields.io/badge/ReconToolKit-v2.0.0-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚠️ ETHICAL USE DISCLAIMER

**ReconToolKit is designed for ethical hacking, educational purposes, and legitimate security assessments only.**

By using this tool, you agree to:
- Only use this tool on systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations in your jurisdiction
- Use the information gathered responsibly and ethically
- Not use this tool for malicious purposes or unauthorized access
- Respect the privacy and security of others

**The developers of ReconToolKit are not responsible for any misuse of this tool.**

## 📋 Overview

ReconToolKit is a comprehensive, enterprise-grade Open-Source Intelligence (OSINT) and network reconnaissance platform built in Python. This advanced version provides cybersecurity professionals, ethical hackers, security researchers, and organizations with a powerful centralized platform for sophisticated intelligence gathering, threat modeling, and continuous monitoring.

### 🌟 Key Features

#### Core Capabilities
- **Advanced Modular Architecture**: Highly extensible with 15+ specialized reconnaissance modules
- **Modern GUI**: Intuitive PyQt5-based interface with advanced visualization capabilities
- **Enterprise Database**: Comprehensive SQLite integration with relationship mapping
- **Secure Storage**: Military-grade encrypted storage for API keys and sensitive data
- **Professional Reporting**: Multi-format reports (PDF, HTML, JSON, CSV, XML) with visualizations

#### Advanced Intelligence Modules
- **Passive OSINT**: Domain enumeration, WHOIS analysis, DNS intelligence, subdomain discovery
- **Active Reconnaissance**: Advanced port scanning, web crawling, vulnerability assessment
- **Social Engineering Intelligence**: Social media analysis, employee intelligence, breach correlation
- **Threat Modeling**: STRIDE methodology, attack surface analysis, risk assessment
- **API Integrations**: Shodan, VirusTotal, Censys, HaveIBeenPwned, SecurityTrails

#### Automation & Monitoring
- **Session Management**: Advanced workflow orchestration and campaign management
- **Continuous Monitoring**: Real-time alerting, change detection, threshold monitoring
- **Data Analysis**: Statistical analysis, pattern recognition, ML-based insights
- **Intelligence Aggregation**: Multi-source threat intelligence correlation

## 🏗️ Advanced Architecture

```
ReconToolKit/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── ADVANCED_MODULES.md    # Advanced modules documentation
├── core/                  # Core application components
│   ├── database.py        # Advanced database management
│   ├── config.py          # Configuration management
│   ├── enhanced_config.py # Enhanced configuration system
│   └── report_generator.py # Core reporting functionality
├── gui/                   # Advanced graphical interface
│   ├── main_window.py     # Main application window
│   ├── dashboard.py       # Advanced dashboard with analytics
│   ├── module_tabs.py     # Dynamic module interface
│   ├── results_viewer.py  # Advanced results management
│   ├── settings_dialog.py # Comprehensive settings
│   ├── about_dialog.py    # About and version info
│   └── dialogs/           # Specialized dialog components
├── modules/               # Comprehensive module system
│   ├── base_module.py     # Base module architecture
│   ├── passive/           # Passive OSINT modules
│   │   ├── domain_enumeration.py
│   │   ├── email_intelligence.py
│   │   └── social_engineering_intel.py
│   ├── active/            # Active reconnaissance modules
│   │   ├── port_scanner.py
│   │   ├── advanced_web_crawler.py
│   │   ├── web_directory_enum.py
│   │   ├── web_fuzzer.py
│   │   ├── vulnerability_scanner.py
│   │   ├── ssl_tls_analyzer.py
│   │   └── network_discovery.py
│   └── utilities/         # Advanced utility modules
│       ├── data_analyzer.py
│       ├── session_manager.py
│       ├── intelligence_aggregator.py
│       ├── api_integration.py
│       ├── advanced_report_generator.py
│       ├── threat_modeling.py
│       └── continuous_monitoring.py
├── wordlists/             # Comprehensive wordlist collection
├── reports/               # Generated reports and analytics
├── logs/                  # Application and module logs
└── data/                  # Database and configuration storage
```

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Quick Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/ReconToolKit.git
   cd ReconToolKit
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

### Alternative Installation with Virtual Environment

1. **Create and activate virtual environment**:
   ```bash
   python -m venv recontoolkit_env
   
   # On Windows
   recontoolkit_env\Scripts\activate
   
   # On Linux/macOS
   source recontoolkit_env/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

## 📦 Dependencies

- **PyQt5**: GUI framework
- **requests**: HTTP library for API calls and web requests
- **dnspython**: DNS toolkit for DNS queries
- **python-whois**: WHOIS lookup functionality
- **beautifulsoup4**: HTML parsing for web scraping
- **pycryptodome**: Cryptographic functions for secure storage
- **reportlab**: PDF report generation
- **jinja2**: Template engine for report generation

## 🛠️ Usage

### Getting Started

1. **Launch the application**:
   ```bash
   python main.py
   ```

2. **Create a new project** from the dashboard or File menu

3. **Configure settings** including API keys, proxy settings, and preferences

4. **Select a reconnaissance module** from the available categories:
   - **Passive OSINT**: Domain enumeration, WHOIS, DNS analysis
   - **Active Reconnaissance**: Port scanning, directory enumeration
   - **Utilities**: Result analysis and reporting tools

5. **Run scans** and view results in real-time

6. **Export results** in various formats (JSON, HTML, CSV)

### Module Categories

#### Passive OSINT Modules

- **Domain Enumeration**: Comprehensive domain analysis including WHOIS, DNS records, and subdomain discovery
- **Email Intelligence**: Email harvesting, validation, and breach correlation
- **Social Engineering Intelligence**: Social media analysis, employee intelligence, and organization profiling

#### Active Reconnaissance Modules

- **Port Scanner**: Advanced TCP/UDP port discovery with service identification
- **Advanced Web Crawler**: Comprehensive website crawling with technology detection
- **Web Directory Enumeration**: Intelligent directory and file discovery
- **Web Fuzzer**: Parameter and input fuzzing capabilities
- **Vulnerability Scanner**: Automated vulnerability detection and analysis
- **SSL/TLS Analyzer**: Certificate and encryption configuration analysis
- **Network Discovery**: Network topology mapping and device identification

#### Advanced Utility Modules

- **Data Analyzer**: Statistical analysis, pattern recognition, and ML-based insights
- **Session Manager**: Workflow orchestration and campaign management
- **Intelligence Aggregator**: Multi-source threat intelligence correlation
- **API Integration**: Unified access to Shodan, VirusTotal, Censys, HIBP, SecurityTrails
- **Advanced Report Generator**: Professional reports with visualizations in multiple formats
- **Threat Modeling**: STRIDE methodology, attack surface analysis, and risk assessment
- **Continuous Monitoring**: Real-time alerting, change detection, and automated monitoring

### Advanced API Integration

ReconToolKit provides enterprise-grade integration with premium intelligence sources:

- **Shodan**: Internet-connected device discovery and vulnerability intelligence
- **VirusTotal**: Malware analysis, URL/domain reputation, and threat intelligence
- **Censys**: Internet-wide scanning data and certificate transparency
- **Have I Been Pwned**: Breach data correlation and password security analysis
- **SecurityTrails**: Historical DNS data, subdomain intelligence, and IP monitoring

Configure API keys in the Settings dialog under the "API Keys" tab for enhanced capabilities.

## ⚙️ Configuration

### Settings Categories

1. **General Settings**:
   - Theme selection (dark/light)
   - Performance tuning (thread count)
   - Auto-save preferences

2. **Network Settings**:
   - Request timeout configuration
   - User agent customization
   - Proxy server setup

3. **API Keys**:
   - Secure storage for external service APIs
   - Encrypted key management

4. **Advanced Settings**:
   - Logging level configuration
   - Custom wordlist management
   - Database optimization

### Proxy Configuration

ReconToolKit supports HTTP/HTTPS proxy configuration for all network requests:

1. Open Settings → Network
2. Enable proxy settings
3. Configure host, port, and authentication
4. Apply settings and restart the application

## 📊 Results and Reporting

### Result Management

- **Real-time Display**: View scan progress and results as they're discovered
- **Persistent Storage**: All results stored in SQLite database
- **Search and Filter**: Advanced filtering by module, status, or keyword
- **Batch Operations**: Export or delete multiple results

### Export Formats

1. **JSON**: Machine-readable format for integration
2. **HTML**: Interactive reports with styling
3. **CSV**: Spreadsheet-compatible format for analysis

### Report Templates

Reports include:
- Executive summary
- Detailed findings
- Methodology used
- Timestamps and metadata
- Recommendations (where applicable)

## 🔧 Development

### Adding New Modules

1. **Create module class**:
   ```python
   from modules.base_module import BaseModule
   
   class MyModule(BaseModule):
       def __init__(self):
           super().__init__(
               name="My Module",
               description="Description of functionality",
               category="passive"
           )
   ```

2. **Implement required methods**:
   - `get_input_fields()`: Define input parameters
   - `validate_inputs()`: Validate user input
   - `run_scan()`: Main scanning logic

3. **Register module** in the appropriate category

### Database Schema

The SQLite database includes:
- **projects**: Project information and metadata
- **scans**: Individual scan records and results
- **configurations**: Application settings (encrypted)
- **wordlists**: Custom wordlist definitions
- **results_summary**: Quick access summary data

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## 🔒 Security Considerations

### Data Protection

- **API Keys**: Stored encrypted using AES-256
- **Local Storage**: Database files stored locally only
- **Network Security**: Proxy support for secure connections
- **Input Validation**: Comprehensive validation to prevent injection attacks

### Ethical Guidelines

- Always obtain explicit permission before scanning
- Respect rate limits and terms of service
- Use responsibly for legitimate security purposes
- Document and report findings appropriately

## 🐛 Troubleshooting

### Common Issues

1. **PyQt5 Installation Issues**:
   ```bash
   pip install --upgrade pip
   pip install PyQt5
   ```

2. **Permission Errors**:
   - Run with appropriate privileges
   - Check file permissions in installation directory

3. **API Connection Issues**:
   - Verify API keys are correctly configured
   - Check network connectivity and proxy settings
   - Review rate limiting and quotas

4. **Database Errors**:
   - Ensure write permissions to data directory
   - Check disk space availability
   - Backup and restore database if corrupted

### Logging

Enable detailed logging by:
1. Settings → Advanced → Log Level → DEBUG
2. Check log files in the `logs/` directory
3. Include relevant log excerpts when reporting issues

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- PyQt5 team for the excellent GUI framework
- DNS Python developers for DNS functionality
- Requests library contributors
- The cybersecurity community for feedback and suggestions

## 📞 Support

For support, bug reports, or feature requests:

1. **GitHub Issues**: [Create an issue](https://github.com/your-username/ReconToolKit/issues)
2. **Documentation**: Check this README and inline help
3. **Community**: Join discussions in the project repository

---

**Remember**: Use ReconToolKit responsibly and ethically. Always ensure you have proper authorization before conducting any reconnaissance activities.

## 🔄 Version History

### v1.0.0 (Current)
- Initial release
- Core OSINT and reconnaissance modules
- Modern PyQt5 GUI
- Database integration
- Export capabilities
- Secure configuration management

---

*ReconToolKit - Empowering ethical reconnaissance and security research*
