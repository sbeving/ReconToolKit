# ReconToolKit: A Comprehensive OSINT & Reconnaissance Platform

![ReconToolKit Logo](https://img.shields.io/badge/ReconToolKit-v1.0.0-blue.svg)
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

ReconToolKit is a powerful, modular, and user-friendly Open-Source Intelligence (OSINT) and network reconnaissance platform built in Python. It provides cybersecurity professionals, ethical hackers, and security researchers with a centralized platform to gather information efficiently and ethically.

### 🌟 Key Features

- **Modular Architecture**: Easy to extend with new reconnaissance modules
- **Modern GUI**: Intuitive PyQt5-based interface with dark/light themes
- **Passive OSINT**: Domain enumeration, WHOIS lookup, DNS analysis, subdomain discovery
- **Active Reconnaissance**: Port scanning, directory enumeration (with proper authorization)
- **Database Integration**: SQLite database for storing scan results and configurations
- **Secure Storage**: Encrypted API key management for external services
- **Export Capabilities**: Generate reports in JSON, HTML, and CSV formats
- **Session Management**: Save and resume reconnaissance sessions
- **Multi-threading**: Concurrent operations for improved performance

## 🏗️ Architecture

```
ReconToolKit/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── core/                  # Core application components
│   ├── database.py        # Database management
│   └── config.py          # Configuration management
├── gui/                   # Graphical user interface
│   ├── main_window.py     # Main application window
│   ├── dashboard.py       # Dashboard widget
│   ├── module_tabs.py     # Module interface tabs
│   ├── results_viewer.py  # Results viewing and management
│   ├── settings_dialog.py # Settings configuration
│   ├── about_dialog.py    # About dialog
│   └── dialogs/           # Additional dialogs
├── modules/               # Reconnaissance modules
│   ├── base_module.py     # Base module class
│   ├── passive/           # Passive OSINT modules
│   ├── active/            # Active reconnaissance modules
│   └── utilities/         # Utility modules
├── wordlists/             # Wordlists for brute-forcing
├── reports/               # Generated reports
└── data/                  # Database and configuration files
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
- **Email & People Search**: Email harvesting and social media profile discovery
- **Website Analysis**: Technology detection and metadata extraction
- **IP Geolocation**: Geographic and network information lookup
- **Code Repository Search**: GitHub/GitLab reconnaissance

#### Active Reconnaissance Modules

- **Port Scanning**: TCP port discovery and service identification
- **Directory Enumeration**: Web directory and file discovery
- **Service Enumeration**: Detailed service version detection

#### Utility Modules

- **Results Viewer**: Advanced filtering and search capabilities
- **Report Generator**: Comprehensive report creation
- **Configuration Manager**: Settings and API key management

### API Integration

ReconToolKit supports integration with various external APIs:

- **VirusTotal**: Domain and IP reputation checking
- **Shodan**: Internet-connected device discovery
- **Hunter.io**: Email discovery and verification
- **GitHub API**: Code repository search
- **SecurityTrails**: Historical DNS data
- **Censys**: Internet scanning data

Configure API keys in the Settings dialog under the "API Keys" tab.

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
