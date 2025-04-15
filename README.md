# WebHunter 🎯

<p align="center">
  <img src="banner.png" alt="WebHunter Banner" width="800"/>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#tools-integrated">Tools</a> •
  <a href="#license">License</a>
</p>

## 🌟 Overview
WebHunter is a powerful and feature-rich subdomain enumeration tool that combines multiple techniques and sources to discover subdomains effectively. It integrates with various popular tools and APIs to provide comprehensive results.

## ✨ Features

### 🔍 Discovery Methods
- **Passive Enumeration**
  - Certificate Transparency Logs
  - DNS Records Analysis
  - OSINT Data Sources
  - API Integration

- **Active Enumeration**
  - DNS Brute Force
  - Zone Transfers
  - Virtual Host Discovery
  - Wildcard Detection

### 🚀 Performance
- Multi-threaded Operations
- Concurrent API Requests
- Smart Rate Limiting
- Resource Optimization

### 📊 Output Options
- Multiple Format Support (JSON, TXT, MD)
- Detailed Reporting
- Custom Output Directory
- Progress Tracking

### ✅ Validation Features
- HTTP/HTTPS Validation
- Status Code Verification
- SSL Certificate Checking
- Screenshot Capture (with --httpx)

## 🔧 Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/webhunter.git

# Navigate to directory
cd webhunter

# Install requirements
pip install -r requirements.txt

# Make script executable (Linux/Mac)
chmod +x sub_enum.py
```

