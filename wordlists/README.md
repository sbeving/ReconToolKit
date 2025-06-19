# ReconToolKit Wordlists Collection

This directory contains comprehensive, high-quality wordlists optimized for reconnaissance and penetration testing activities. Each wordlist has been carefully curated to provide maximum coverage while maintaining efficiency.

## 📋 Available Wordlists

### 1. **subdomains_comprehensive.txt** (450+ entries)
- **Purpose**: Subdomain enumeration and discovery
- **Content**: Administrative panels, API endpoints, development environments, geographic regions, services, and technology-specific subdomains
- **Use Cases**: 
  - Subdomain brute forcing with tools like `gobuster`, `ffuf`, `sublist3r`
  - DNS enumeration with `dnsrecon`, `fierce`, `amass`
  - Certificate transparency log analysis

### 2. **directories_comprehensive.txt** (800+ entries)
- **Purpose**: Web directory and file discovery
- **Content**: Admin panels, configuration files, backup locations, CMS paths, API endpoints, and sensitive directories
- **Use Cases**:
  - Directory brute forcing with `dirb`, `gobuster`, `ffuf`
  - Web application enumeration
  - Hidden content discovery

### 3. **sensitive_files.txt** (1000+ entries)
- **Purpose**: Discovery of sensitive and configuration files
- **Content**: Configuration files, backups, logs, keys, certificates, database files, version control files
- **Use Cases**:
  - Sensitive file discovery
  - Information disclosure testing
  - Configuration review
- **⚠️ WARNING**: Use only on authorized targets

### 4. **common_passwords.txt** (2000+ entries)
- **Purpose**: Password brute force attacks
- **Content**: Default passwords, keyboard patterns, common words, years, names, company patterns
- **Use Cases**:
  - SSH/RDP brute forcing
  - Web application login attacks
  - Default credential testing
- **⚠️ WARNING**: Use only on authorized targets

### 5. **common_usernames.txt** (1500+ entries)
- **Purpose**: Username enumeration and brute forcing
- **Content**: Default system accounts, common names, job titles, service accounts, department names
- **Use Cases**:
  - User enumeration
  - Login brute forcing
  - LDAP/AD enumeration
  - Email harvesting validation

### 6. **api_endpoints.txt** (600+ entries)
- **Purpose**: API endpoint discovery
- **Content**: REST API paths, GraphQL endpoints, authentication endpoints, CRUD operations, versioning patterns
- **Use Cases**:
  - API discovery and enumeration
  - REST API testing
  - Microservices enumeration
  - API security testing

### 7. **http_status_fuzzing.txt** (500+ entries)
- **Purpose**: HTTP status code based discovery
- **Content**: Paths designed to trigger specific HTTP status codes (401, 403, 404, 500, etc.)
- **Use Cases**:
  - Error page discovery
  - Access control testing
  - Application behavior analysis
  - Hidden endpoint discovery

### 8. **technology_specific.txt** (2000+ entries)
- **Purpose**: Technology and framework specific enumeration
- **Content**: WordPress, Drupal, Laravel, Django, React, Angular, Java, .NET, and many other technology-specific paths
- **Use Cases**:
  - CMS enumeration
  - Framework-specific testing
  - Technology fingerprinting
  - Targeted reconnaissance

## 🛠️ Usage Examples

### Subdomain Enumeration
```bash
# Using gobuster
gobuster dns -d target.com -w wordlists/subdomains_comprehensive.txt

# Using ffuf
ffuf -w wordlists/subdomains_comprehensive.txt -u https://FUZZ.target.com

# Using amass
amass enum -brute -w wordlists/subdomains_comprehensive.txt -d target.com
```

### Directory Brute Forcing
```bash
# Using gobuster
gobuster dir -u https://target.com -w wordlists/directories_comprehensive.txt

# Using ffuf
ffuf -w wordlists/directories_comprehensive.txt -u https://target.com/FUZZ

# Using dirb
dirb https://target.com wordlists/directories_comprehensive.txt
```

### API Endpoint Discovery
```bash
# Using ffuf for API discovery
ffuf -w wordlists/api_endpoints.txt -u https://target.com/api/FUZZ

# Using gobuster for API enumeration
gobuster dir -u https://target.com/api -w wordlists/api_endpoints.txt
```

### Sensitive File Discovery
```bash
# Using ffuf
ffuf -w wordlists/sensitive_files.txt -u https://target.com/FUZZ

# Using gobuster
gobuster dir -u https://target.com -w wordlists/sensitive_files.txt -x php,txt,conf,bak
```

### Technology-Specific Testing
```bash
# WordPress enumeration
ffuf -w wordlists/technology_specific.txt -u https://target.com/FUZZ -mc 200,403,301,302

# Framework detection
gobuster dir -u https://target.com -w wordlists/technology_specific.txt -s 200,204,301,302,403
```

## 🎯 Optimization Tips

### 1. **Combine Wordlists**
```bash
# Merge multiple wordlists for comprehensive coverage
cat wordlists/directories_comprehensive.txt wordlists/sensitive_files.txt > combined_dirs.txt
```

### 2. **Filter by Response Codes**
```bash
# Focus on interesting status codes
ffuf -w wordlists/directories_comprehensive.txt -u https://target.com/FUZZ -mc 200,401,403,301,302
```

### 3. **Add File Extensions**
```bash
# Test with common extensions
gobuster dir -u https://target.com -w wordlists/directories_comprehensive.txt -x php,html,asp,aspx,jsp,txt,conf,bak
```

### 4. **Rate Limiting**
```bash
# Avoid overwhelming the target
ffuf -w wordlists/directories_comprehensive.txt -u https://target.com/FUZZ -rate 10
```

## 🔧 Integration with ReconToolKit

These wordlists are designed to be seamlessly integrated with the ReconToolKit platform:

1. **Automated Discovery**: Use wordlists in automated reconnaissance workflows
2. **Custom Scans**: Select specific wordlists based on target technology
3. **Progress Tracking**: Monitor enumeration progress through the GUI
4. **Result Analysis**: Correlate findings across different wordlist types

## 📊 Wordlist Statistics

| Wordlist | Entries | Size | Primary Use Case |
|----------|---------|------|------------------|
| Subdomains Comprehensive | 450+ | ~15KB | Subdomain Discovery |
| Directories Comprehensive | 800+ | ~35KB | Directory Enumeration |
| Sensitive Files | 1000+ | ~45KB | Information Disclosure |
| Common Passwords | 2000+ | ~50KB | Brute Force Attacks |
| Common Usernames | 1500+ | ~30KB | User Enumeration |
| API Endpoints | 600+ | ~20KB | API Discovery |
| HTTP Status Fuzzing | 500+ | ~25KB | Status Code Testing |
| Technology Specific | 2000+ | ~80KB | Framework Testing |

## 🛡️ Ethical Usage Guidelines

### ✅ Authorized Use
- Penetration testing with explicit permission
- Security assessments on owned infrastructure
- Bug bounty programs with defined scope
- Educational purposes in controlled environments
- Security research with proper authorization

### ❌ Prohibited Use
- Unauthorized access to systems
- Malicious activities
- Harassment or disruption of services
- Violation of terms of service
- Any illegal activities

## 🔄 Maintenance and Updates

These wordlists are regularly updated to include:
- New technology patterns and frameworks
- Emerging attack vectors
- Common misconfigurations
- Latest security research findings

### Version History
- **v1.0**: Initial comprehensive collection
- **v1.1**: Enhanced API endpoints and technology-specific patterns
- **v1.2**: Added HTTP status fuzzing and sensitive files expansion

## 🤝 Contributing

To contribute to these wordlists:
1. Fork the ReconToolKit repository
2. Add new entries following existing patterns
3. Test entries for effectiveness
4. Submit pull request with detailed description
5. Ensure compliance with ethical guidelines

## 📚 Additional Resources

### Recommended Tools
- **gobuster**: Fast directory/file & DNS busting tool
- **ffuf**: Fast web fuzzer written in Go
- **dirb**: Web Content Scanner
- **amass**: In-depth Attack Surface Mapping
- **sublist3r**: Subdomain enumeration tool

### Learning Resources
- OWASP Web Security Testing Guide
- PortSwigger Web Security Academy
- HackerOne Hacktivity Reports
- Bug Bounty Methodology by Jason Haddix

## ⚖️ Legal Disclaimer

These wordlists are provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using these tools against any target. The creators and contributors are not responsible for any misuse or damage caused by these wordlists.

Always obtain explicit written permission before conducting security testing activities.

---

**Happy Hunting! 🎯**

For questions, suggestions, or contributions, please open an issue in the ReconToolKit repository.
