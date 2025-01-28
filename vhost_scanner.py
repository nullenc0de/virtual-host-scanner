#!/usr/bin/env python3

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp
import dns.resolver
from aiohttp import ClientTimeout
from dns.exception import DNSException

@dataclass
class ScanResult:
    """Data class for storing scan results"""
    hostname: str
    ip_mode: bool
    mode: str
    similarity: float  # Will be either 0.0 or 100.0
    curl_command: str
    response_code: int
    headers: Dict[str, str]
    content_hash: str

class VHostScanner:
    """Enhanced Virtual Host Scanner"""
    
    def __init__(
        self,
        target_url: str,
        wordlist: Optional[List[str]] = None,
        ip_list: Optional[List[str]] = None,
        threads: int = 10,
        timeout: int = 10,
        verbose: bool = False,
        ip_mode: bool = False
    ):
        """Initialize VHost Scanner"""
        # Configure our own logger with a minimal format
        self.logger = logging.getLogger('vhostscanner')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # If there are no handlers, add a console handler
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.ip_mode = ip_mode
        self.ip_list = ip_list
        self.wordlist = wordlist or self._generate_wordlist()
        
        # Initialize state
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.dns_cache = {}
        self.seen_results = set()

        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.ip_mode = ip_mode
        self.ip_list = ip_list
        
        # Load or generate wordlist
        self.wordlist = wordlist or self._generate_wordlist()
        
        # Initialize state
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.dns_cache = {}
        self.seen_results = set()

    @staticmethod
    def _generate_wordlist() -> List[str]:
        """Generate an enhanced wordlist of potential virtual hosts"""
        base_words = [
            # Common environments
            "dev", "staging", "prod", "test", "uat", "qa",
            # Services
            "api", "admin", "portal", "app", "auth", "cdn",
            # Infrastructure
            "internal", "backend", "private", "public", "secure",
            # Standard prefixes
            "www", "mail", "remote", "vpn", "intranet",
            # Cloud and DevOps
            "docker", "k8s", "ci", "jenkins", "git",
            # Versioning
            "v1", "v2", "v3", "beta", "alpha",
            # Additional services
            "jira", "confluence", "wiki", "docs", "support"
        ]

        variations = []
        for word in base_words:
            variations.extend([
                word,
                f"{word}-api",
                f"api-{word}",
                f"{word}-test",
                f"{word}-1",
                f"{word}-2"
            ])

        return sorted(list(set(variations)))

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_loopback or 
                       ip_obj.is_link_local or 
                       ip_obj.is_reserved or
                       ip_obj.is_multicast)
        except ValueError:
            return False

    async def _resolve_domain_ips_async(self, domain: str) -> List[str]:
        """Asynchronously resolve domain to IP addresses with caching"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]

        ips = set()
        try:
            resolver = dns.resolver.Resolver()
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                resolver.resolve,
                domain,
                'A'
            )
            
            for rdata in answers:
                ip = str(rdata)
                if self._is_valid_ip(ip):
                    ips.add(ip)

        except DNSException as e:
            self.logger.debug(f"DNS resolution failed for {domain}: {e}")

        result = list(ips)
        self.dns_cache[domain] = result
        return result

    async def _fetch_url_content_async(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[str], Dict[str, str], int]:
        """Fetch URL content asynchronously with error handling"""
        timeout = ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=headers,
                    ssl=False,  # Disable SSL verification for scanning
                    allow_redirects=True
                ) as response:
                    content = await response.text()
                    return content, dict(response.headers), response.status
                    
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.debug(f"Error fetching {url}: {e}")
            return None, {}, 0

    async def _scan_target_async(
        self,
        domain: str,
        target: str,
        mode: str = 'default'
    ) -> Optional[ScanResult]:
        """Scan a target asynchronously"""
        try:
            # Determine test hostname and URL
            if mode == 'default':
                test_hostname = f"{target}.{domain}" if not self.ip_mode else target
                test_url = f"http://{domain}"
            elif mode == 'ip_host':
                test_hostname = target
                test_url = f"http://{domain}"
            else:  # host_ip mode
                test_hostname = domain
                test_url = f"http://{target}"

            # Fetch baseline content
            baseline_content, baseline_headers, baseline_code = await self._fetch_url_content_async(test_url)
            if baseline_content is None:
                return None

            # Fetch content with test hostname
            test_content, test_headers, test_code = await self._fetch_url_content_async(
                test_url,
                headers={'Host': test_hostname}
            )
            if test_content is None:
                return None

            # Different status codes means different responses
            are_different = baseline_code != test_code

            # If status codes match, compare content
            if not are_different:
                # Clean content (remove HTML tags and normalize whitespace)
                baseline_clean = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', baseline_content)).strip().lower()
                test_clean = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', test_content)).strip().lower()
                
                # Compare cleaned content hashes
                baseline_hash = hashlib.md5(baseline_clean.encode()).hexdigest()
                test_hash = hashlib.md5(test_clean.encode()).hexdigest()
                
                are_different = baseline_hash != test_hash

            if self.verbose:
                self.logger.debug(f"Comparing {test_hostname} (code: {test_code}) with baseline (code: {baseline_code})")
                self.logger.debug(f"Content is {'different' if are_different else 'identical'}")

            # Create unique result key
            result_key = (test_hostname, test_code, are_different, mode)
            if result_key in self.seen_results:
                return None
            self.seen_results.add(result_key)

            # Return result if responses are different
            if are_different:
                test_hash = hashlib.md5(test_content.encode()).hexdigest()
                return ScanResult(
                    hostname=test_hostname,
                    ip_mode=self.ip_mode,
                    mode=mode,
                    similarity=0.0 if are_different else 100.0,
                    curl_command=f"curl -k -H 'Host: {test_hostname}' {test_url}",
                    response_code=test_code,
                    headers=test_headers,
                    content_hash=test_hash
                )

        except Exception as e:
            self.logger.debug(f"Error scanning {target}: {e}")

        return None

    async def scan_async(self) -> List[Dict[str, Any]]:
        """Perform asynchronous scanning"""
        self.scan_start_time = time.time()
        
        try:
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc or parsed_url.path
        except Exception as e:
            self.logger.error(f"Invalid URL: {e}")
            return []

        # Determine targets
        try:
            if self.ip_list:
                # Use provided IP list
                targets = [ip.strip() for ip in self.ip_list if self._is_valid_ip(ip.strip())]
                invalid_ips = [ip for ip in self.ip_list if not self._is_valid_ip(ip.strip())]
                if invalid_ips:
                    self.logger.warning(f"Skipping invalid IPs: {', '.join(invalid_ips)}")
            else:
                # Use DNS resolution or wordlist
                targets = (await self._resolve_domain_ips_async(domain) 
                          if self.ip_mode else self.wordlist)
        except Exception as e:
            self.logger.error(f"Error determining targets: {e}")
            return []

        # Log only once at the start of scanning
        self.logger.info(f"Starting scan with {len(targets)} target{'s' if len(targets) != 1 else ''}")

        # Prepare scan modes
        scan_modes = ['default']
        if self.ip_mode or self.ip_list:
            scan_modes.extend(['ip_host', 'host_ip'])

        # Create scanning tasks
        tasks = []
        for mode in scan_modes:
            for target in targets:
                tasks.append(self._scan_target_async(domain, target, mode))

        # Run scans concurrently
        results = []
        chunk_size = 50  # Process in chunks to manage memory
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            for result in chunk_results:
                if isinstance(result, ScanResult):
                    results.append(asdict(result))

        self.scan_end_time = time.time()
        return self._deduplicate_results(results)

    def scan(self) -> List[Dict[str, Any]]:
        """Main scanning function"""
        return asyncio.run(self.scan_async())

    @staticmethod
    def _deduplicate_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate results with advanced filtering"""
        unique_results = []
        seen = set()
        
        # First, sort results to prioritize 200 responses and unique hostnames
        sorted_results = sorted(
            results,
            key=lambda x: (
                0 if x['response_code'] == 200 else x['response_code'],  # 200s first
                x['hostname'],
                x['mode']
            )
        )
        
        for result in sorted_results:
            # Create a unique signature that identifies truly unique responses
            signature = (
                result['hostname'],
                result['response_code'],
                result['content_hash']
            )
            
            # For IPs that return the same response code and content, only keep one entry
            if result['hostname'].replace('.', '').isdigit():  # If hostname is an IP
                ip_signature = (
                    result['hostname'],
                    result['response_code']
                )
                if ip_signature in seen:
                    continue
                seen.add(ip_signature)
            # For regular hostnames, keep unique content responses
            elif signature not in seen:
                seen.add(signature)
            else:
                continue
                
            unique_results.append(result)

        return unique_results

def main():
    """Main entry point"""
    # Suppress default logging and set up our custom format
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    logging.basicConfig(
        format='%(message)s',
        level=logging.CRITICAL  # Set root logger to high level to suppress extra messages
    )

    parser = argparse.ArgumentParser(description='Enhanced Virtual Host Scanner')
    
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('--ip-mode', action='store_true',
                          help='Enable IP-based scanning using DNS resolution')
    target_group.add_argument('--ip-list', type=str,
                          help='File containing list of IP addresses to scan')
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL')
    parser.add_argument('-w', '--wordlist',
                       help='Custom wordlist file path')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output',
                       help='Output file path (JSON format)')
    parser.add_argument('-g', '--grepable', action='store_true',
                       help='Output results in grepable format')
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Normalize URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = f'http://{args.url}'

    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading wordlist: {e}")
            sys.exit(1)

    # Load IP list if provided
    ip_list = None
    if args.ip_list:
        try:
            with open(args.ip_list, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(ip_list)} IP addresses from {args.ip_list}")
        except Exception as e:
            logger.error(f"Error reading IP list: {e}")
            sys.exit(1)

    try:
        # Initialize scanner
        scanner = VHostScanner(
            target_url=args.url,
            wordlist=wordlist,
            ip_list=ip_list,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            ip_mode=args.ip_mode
        )

        # Perform scan
        results = scanner.scan()

        # Calculate scan statistics
        scan_time = scanner.scan_end_time - scanner.scan_start_time
        total_targets = len(scanner.wordlist if not args.ip_mode else scanner.dns_cache.get(urlparse(args.url).netloc, []))

        # Prepare scan report
        scan_report = {
            'scan_info': {
                'target_url': args.url,
                'total_targets': total_targets,
                'discovered_hosts': len(results),
                'scan_duration': round(scan_time, 2),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'settings': {
                    'ip_mode': args.ip_mode,
                    'threads': args.threads,
                    'timeout': args.timeout
                }
            },
            'results': results
        }

        # Handle output
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(scan_report, f, indent=2)
                logger.info(f"Results saved to {args.output}")
            except Exception as e:
                logger.error(f"Error saving results: {e}")
                sys.exit(1)

        # Display results
        if args.json:
            print(json.dumps(scan_report, indent=2))
        else:
            # Print summary
            print("\nScan Summary")
            print("═" * 50)
            print(f"Target URL:       {args.url}")
            print(f"Total Targets:    {total_targets}")
            print(f"Discovered Hosts: {len(results)}")
            print(f"Scan Duration:    {scan_time:.2f} seconds")
            print("═" * 50)

            if results:
                print("\nDiscovered Virtual Hosts")
                print("─" * 50)
                for result in results:
                    print(f"\n[+] Host: {result['hostname']}")
                    print(f"    Response:  HTTP {result['response_code']}")
                    print(f"    Mode:      {result['mode']}")
                    print(f"    Command:   {result['curl_command']}")
                    if args.verbose and result['headers']:
                        print("\n    Response Headers:")
                        for header, value in sorted(result['headers'].items()):
                            print(f"      {header}: {value}")
                    print("─" * 50)
            else:
                print("\nNo virtual hosts discovered.")

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
