# Project Sentient 2.0

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-CC%20BY--NC--ND%204.0-red.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/)
[![Version](https://img.shields.io/badge/version-1.0.2-green.svg)](https://github.com/x0as/Sentient)

**Project Sentient 2.0** is an advanced AI-powered cybersecurity toolkit that combines the intelligence of Google's Gemini API with comprehensive security analysis modules. This conversational AI assistant is designed for cybersecurity professionals, researchers, and ethical hackers who need an intelligent, modular platform for security analysis, OSINT gathering, and digital forensics.

---

## 🚀 Features

### 🤖 AI-Powered Analysis
- **Conversational AI Interface:** Natural language interaction powered by Google Gemini API
- **Intelligent Context Awareness:** Remembers analysis results and provides contextual recommendations
- **Memory Persistence:** MongoDB integration for storing analysis history and results

### 🔍 Security Analysis
- **File Analysis:** Deep examination of files for malicious content and metadata extraction
- **VirusTotal Integration:** Automated malware scanning and threat intelligence
- **PDF & Image Analysis:** Extract metadata, hidden content, and security risks
- **Hash Tools:** Generate, identify, and analyze various hash types
- **Firewall Protection:** Security configuration analysis and recommendations

### 🌐 Network Security
- **Website Vulnerability Scanner:** SQL injection, XSS, and security misconfiguration detection
- **Port Scanner:** Comprehensive port scanning with service detection
- **Directory Brute Force:** Discover hidden directories and files
- **SSL/TLS Checker:** Certificate analysis and security validation
- **Subdomain Enumeration:** Comprehensive subdomain discovery
- **Subdomain Takeover Detection:** Identify vulnerable subdomain configurations

### 📊 Intelligence Gathering (OSINT)
- **WHOIS & DNS Tools:** Domain intelligence and DNS analysis
- **GeoIP & Reverse IP Lookup:** Geographic and hosting information
- **Phone & Email Lookup:** Contact information intelligence
- **Username Checker:** Social media and platform username analysis
- **Email Spoof Testing:** Email security and authenticity verification
- **Email Tracking:** Email delivery and engagement analysis

### 🔒 Cryptography & Authentication
- **JWT Analyzer:** JSON Web Token decoding and security analysis
- **Password Strength Testing:** Comprehensive password security evaluation
- **Breach Checker:** Check credentials against known data breaches
- **URL Expander:** Analyze and expand shortened URLs safely

### 📈 Advanced Analysis
- **CVE Search:** Latest vulnerability research and threat intelligence
- **Packet Analyzer:** Network traffic analysis and packet inspection
- **Log Analyzer:** Security event correlation and anomaly detection
- **Traffic Generation:** Realistic traffic simulation for testing

### 🛠️ Automation & Integration
- **Modular Architecture:** Easy-to-extend plugin system
- **Batch Processing:** Automated scanning and analysis workflows
- **Export Capabilities:** Multiple output formats for reporting
- **API Integration:** Seamless third-party service integration

---

## 🗄️ Database & Persistence

Sentient 2.0 uses MongoDB for persistent storage of analysis results, scan history, and configuration data. This enables:

- **Session Continuity:** Resume analysis sessions with full context
- **Historical Analysis:** Track changes and trends over time
- **Result Correlation:** Cross-reference findings across different scans
- **Custom Intelligence:** Build your own threat intelligence database

**MongoDB Setup:**
You will be prompted to enter your MongoDB connection string when starting Sentient. If you need assistance setting up MongoDB or require access to a shared instance, contact: **muhammadhuzaifakhalidaziz@gmail.com**

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.7 or higher
- MongoDB instance (local or cloud)
- Google Gemini API key

### Quick Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/x0as/Sentient.git
   cd Sentient
   ```

2. **Install using pip (Recommended):**
   ```bash
   pip install -e .
   ```

   **Or install dependencies manually:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Sentient:**
   ```bash
   # Using the installed console script
   sentient
   
   # Or run directly
   python -m sentient.main
   ```

### Windows Users
For Windows users, you can use the provided batch files:
- `Setup.bat` - Automated installation
- `Start.bat` - Quick start script

### Configuration

1. **API Key Setup:** You'll be prompted to enter your Google Gemini API key on first run
2. **MongoDB Connection:** Provide your MongoDB connection string when prompted
3. **Premium Features:** Contact muhammadhuzaifakhalidaziz@gmail.com for premium API access

---

## 💻 Usage

### Interactive Mode
Launch Sentient and interact through natural language:

```bash
sentient
```

### Command Examples

```bash
# Website Security Analysis
"scan website example.com for vulnerabilities"
"check SSL certificate for example.com"
"enumerate subdomains for example.com"

# File Analysis
"analyze file /path/to/suspicious.exe"
"scan file with virustotal /path/to/file.pdf"
"extract metadata from image.jpg"

# Network Intelligence
"port scan 192.168.1.1"
"geoip lookup 8.8.8.8"
"reverse IP lookup 1.2.3.4"

# OSINT & Research
"email lookup test@example.com"
"phone lookup +1234567890"
"username check across platforms john_doe"
"whois lookup example.com"

# Security Analysis
"check password strength MyPassword123"
"decode JWT token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
"check breach database for email@example.com"

# Advanced Analysis
"search CVE for apache"
"analyze packet capture /path/to/capture.pcap"
"check subdomain takeover for example.com"

# Utility Commands
"expand URL bit.ly/shortlink"
"generate hash for text or file"
"export results to report.txt"
```

### Batch Operations
```bash
# Multiple targets
"scan multiple websites: example1.com, example2.com, example3.com"

# Automated workflows
"full security assessment for example.com"
```

---

## 🏗️ Architecture

### Project Structure
```
sentient/
├── main.py              # Main entry point and AI interface
├── chromedriver.exe     # WebDriver for browser automation
└── modules/             # Security analysis modules
    ├── breach_checker.py        # Data breach verification
    ├── cve_search.py           # CVE database search
    ├── dir_bruteforce.py       # Directory enumeration
    ├── dns_tools.py            # DNS analysis tools
    ├── Email_Lookup.py         # Email intelligence
    ├── email_spoof_test.py     # Email security testing
    ├── Email_Tracker.py        # Email tracking analysis
    ├── file_analysis.py        # File security analysis
    ├── firewall_protection.py  # Firewall configuration
    ├── geoip_lookup.py         # Geographic IP analysis
    ├── hash_tools.py           # Cryptographic hash utilities
    ├── image_metadata.py       # Image forensics
    ├── jwt_analyzer.py         # JWT security analysis
    ├── log_analyzer.py         # Log file analysis
    ├── packet_analyzer.py      # Network packet analysis
    ├── password_strength.py    # Password security assessment
    ├── pdf_analyzer.py         # PDF security analysis
    ├── Phone_Lookup.py         # Phone number intelligence
    ├── port_scanner.py         # Network port scanning
    ├── real_traffic.py         # Traffic simulation
    ├── reverse_ip.py           # Reverse IP lookup
    ├── ssl_checker.py          # SSL/TLS analysis
    ├── subdomain_enum.py       # Subdomain discovery
    ├── subdomain_takeover.py   # Subdomain security analysis
    ├── traffic_sender.py       # Traffic generation
    ├── url_expander.py         # URL analysis and expansion
    ├── username_checker.py     # Username intelligence
    ├── virustotal_scan.py      # VirusTotal integration
    └── website_scanner.py      # Web application security
```

### Core Technologies
- **AI Framework:** Google Generative AI (Gemini)
- **Database:** MongoDB for persistence
- **Network:** Scapy for packet analysis
- **Web:** Selenium for browser automation
- **Security:** Custom modules for specialized analysis

---

## 🔧 Development

### Adding Custom Modules

Sentient's modular architecture makes it easy to add new security analysis capabilities:

1. **Create a new module in `sentient/modules/`:**
   ```python
   # my_custom_module.py
   def my_analysis_function(target, options=None):
       """
       Custom analysis function
       Args:
           target: The target to analyze
           options: Additional options
       Returns:
           dict: Analysis results
       """
       results = {
           'status': 'success',
           'data': [],
           'summary': 'Analysis complete'
       }
       return results
   ```

2. **Import in main.py:**
   ```python
   from .modules import my_custom_module
   ```

3. **Register with the AI interface** by adding command patterns to the natural language processor.

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with a clear description

---

## 📋 Requirements

### Python Dependencies
- `google-generativeai>=0.3.0` - AI integration
- `pymongo>=4.0.0` - Database connectivity
- `requests>=2.25.1` - HTTP client
- `selenium` - Web automation
- `scapy>=2.4.5` - Packet analysis
- `beautifulsoup4>=4.9.3` - HTML parsing
- `cryptography>=3.4.8` - Cryptographic functions
- `dnspython>=2.1.0` - DNS operations
- `python-whois>=0.7.3` - WHOIS lookup
- `tabulate>=0.8.9` - Data formatting
- `fuzzywuzzy>=0.18.0` - String matching
- `colorama>=0.4.4` - Terminal colors

### System Requirements
- **Operating System:** Windows, macOS, or Linux
- **Python:** 3.7 or higher
- **Memory:** Minimum 4GB RAM (8GB recommended)
- **Network:** Internet connection for API access and external scans
- **Storage:** 1GB free space for dependencies and logs

---

## 🛡️ Security & Ethics

### Ethical Use Policy
Project Sentient 2.0 is designed exclusively for:
- **Educational purposes** in cybersecurity learning
- **Authorized security testing** with proper permissions
- **Research** in cybersecurity and threat intelligence
- **Professional security assessments** by qualified personnel

### Legal Compliance
- **Always obtain proper authorization** before testing systems you do not own
- **Respect privacy** and data protection laws
- **Follow responsible disclosure** practices for discovered vulnerabilities
- **Comply with local and international laws** regarding cybersecurity tools

### Built-in Safeguards
- Rate limiting to prevent abuse
- Logging for accountability
- Warning prompts for potentially sensitive operations
- Integration with legitimate security APIs only

---

## ⚖️ License

This project is licensed under the **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License (CC BY-NC-ND 4.0)**.

### License Terms:
- ✅ **Attribution Required:** You must give appropriate credit when sharing
- ❌ **No Commercial Use:** Cannot be used for commercial purposes
- ❌ **No Derivatives:** Cannot distribute modified versions
- ✅ **Personal Use:** Free for educational and personal cybersecurity research

For complete license details, see: [CC BY-NC-ND 4.0 License](https://creativecommons.org/licenses/by-nc-nd/4.0/)

---

## ⚠️ Disclaimer

### Legal Notice
Project Sentient 2.0 is intended **exclusively** for:
- Educational cybersecurity learning
- Authorized penetration testing
- Academic and professional research
- Ethical security assessments

### User Responsibility
- **The creator is NOT responsible** for any misuse, illegal activity, or damage
- **Users are solely responsible** for ensuring compliance with all applicable laws
- **Always obtain proper authorization** before testing systems
- **Respect privacy and data protection laws** in your jurisdiction

### Professional Use
This tool is designed for cybersecurity professionals who understand the legal and ethical implications of security testing. Improper use may violate computer crime laws in your jurisdiction.

---

## 🎯 Version Information

- **Current Version:** 1.0.2
- **Author:** x0as
- **Last Updated:** July 2025
- **Python Compatibility:** 3.7+
- **Platform Support:** Windows, macOS, Linux

---

*Project Sentient 2.0 - Intelligent Cybersecurity Analysis Platform*
