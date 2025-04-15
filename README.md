# WebHunter - Advanced Subdomain Enumeration Tool

## Description
A powerful subdomain enumeration tool that combines multiple techniques and sources to discover subdomains effectively.

## Features
- 🔍 **Multiple Discovery Methods**
  - Passive enumeration using various APIs and services
  - Active enumeration with brute-force capabilities
  - Integration with popular tools (Amass, Subfinder, Assetfinder, etc.)
  - Certificate transparency logs scanning
  - DNS records analysis

- 🚀 **Performance Optimization**
  - Multi-threaded scanning
  - Concurrent API requests
  - Efficient memory management
  - Smart rate limiting to avoid API blocks

- 📊 **Advanced Output Options**
  - Multiple format support (JSON, TXT, MD)
  - Detailed reporting with vulnerability assessment
  - Export options for further analysis
  - Progress tracking with rich console output

- ✅ **Validation & Filtering**
  - Active subdomain validation
  - HTTP/HTTPS status checking
  - Response code analysis
  - Web service identification
  - Screenshot capture capability (with --httpx)

- 🛡️ **Security Features**
  - Rate limiting protection
  - API key management
  - Error handling and recovery
  - Proxy support for anonymous scanning

- 🔧 **Customization Options**
  - Configurable thread count
  - Custom wordlist support
  - Adjustable timeout settings
  - Multiple output directory options

## Installation
```bash
git clone https://github.com/knobrazz/sub_enum.git
cd sub_enum
pip install -r requirements.txt
```

## Acknowledgments & Credits

This project utilizes several amazing open-source tools and libraries. We're grateful to their creators and maintainers:

### Core Libraries
- [Requests](https://github.com/psf/requests) - Apache License 2.0
- [Rich](https://github.com/Textualize/rich) - MIT License
- [HTTPX](https://github.com/encode/httpx) - BSD License
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) - MIT License
- [Colorama](https://github.com/tartley/colorama) - BSD License

### Data Sources & APIs
- [VirusTotal](https://www.virustotal.com/gui/home/search) - Free API usage within terms
- [SecurityTrails](https://securitytrails.com/) - API usage within terms
- [Crt.sh](https://crt.sh/) - Certificate Transparency logs
- [CertSpotter](https://sslmate.com/certspotter/) - Cert Transparency search
- [DNSDumpster](https://dnsdumpster.com/) - DNS recon & research
- [HackerTarget](https://hackertarget.com/) - Public API usage

### External Tools Integration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - MIT License
- [Amass](https://github.com/OWASP/Amass) - Apache License 2.0
- [Assetfinder](https://github.com/tomnomnom/assetfinder) - MIT License
- [Findomain](https://github.com/Findomain/Findomain) - GPL-3.0 License

## Legal Notice
This tool is meant for security research and penetration testing with proper authorization. Users are responsible for complying with applicable laws and terms of service of integrated tools and APIs.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

