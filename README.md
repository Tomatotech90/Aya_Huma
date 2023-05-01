# Aya_Huma

[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-green.svg?style=flat-square)](https://www.python.org/downloads/)
![OS](https://img.shields.io/badge/Tested%20On-Linux-yellowgreen.svg?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)

This script is a comprehensive cybersecurity tool designed for scanning and analyzing network targets. It utilizes various libraries and tools to perform tasks such as certificate transparency checks, subdomain enumeration, website analysis, WAF detection, and SQL injection scanning, among others.

## Dependencies

Before running the script, ensure that you have all the required Python libraries and external tools installed.

### Python Libraries

- [colorama](https://pypi.org/project/colorama/): Used for displaying colored ASCII art.
- [requests](https://pypi.org/project/requests/): Required for making HTTP requests.

### External Tools and Utilities

- [openssl](https://www.openssl.org/): For SSL/TLS-related tasks.
- [curl](https://curl.se/): A command-line tool for transferring data with URLs.
- [waybackurls](https://github.com/tomnomnom/waybackurls): Fetching URLs from the Wayback Machine.
- [whatweb](https://github.com/urbanadventurer/WhatWeb): A website fingerprinting tool.
- [wafw00f](https://github.com/EnableSecurity/wafw00f): A tool for detecting Web Application Firewalls (WAFs).
- [aquatone](https://github.com/michenriksen/aquatone): A domain flyover tool for subdomain discovery and screenshotting.
- [sqlmap](http://sqlmap.org/): An open-source penetration testing tool for automating SQL injection detection and exploitation.
- [dirb](https://tools.kali.org/web-applications/dirb): A web content scanner for discovering existing and hidden web resources.
- [ffuf](https://github.com/ffuf/ffuf): A fast web fuzzer for discovering elements within web applications.
- [jq](https://stedolan.github.io/jq/): A lightweight command-line JSON processor.
- [nmap](https://nmap.org/): A powerful network scanning tool.

## Usage

In Linux or macOS, you can run the script using the following command, with root privileges:

```bash
sudo python3 script_name.py
