#!/usr/bin/env python3

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from typing import List, Dict, Any, Optional, Tuple

class VHostScanner:
    def __init__(
        self,
        target_url: str,
        wordlist: Optional[List[str]] = None,
        threads: int = 10,
        timeout: int = 10,
        verbose: bool = False,
        ip_mode: bool = False
    ):
        """
        Initialize VHost Scanner

        :param target_url: Base URL to scan
        :param wordlist: Custom wordlist of potential vhosts
        :param threads: Number of concurrent threads
        :param timeout: Connection timeout in seconds
        :param verbose: Enable verbose output
        :param ip_mode: Enable IP-based scanning
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        self.logger.addHandler(console_handler)

        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.ip_mode = ip_mode

        # Load wordlist
        self.wordlist = wordlist or self._generate_enhanced_wordlist()

        # Results storage
        self.results = []

        # Scan metadata
        self.scan_start_time = None
        self.scan_end_time = None

    @staticmethod
    def _generate_enhanced_wordlist() -> List[str]:
        """
        Generate an enhanced wordlist of potential virtual hosts
        """
        base_list = [
            # Standard environments
            "dev", "development", "staging", "stage",
            "prod", "production", "test", "testing",
            "qa", "uat", "demo", "admin", "api",

            # Infrastructure and access
            "internal", "backend", "private", "secure",
            "corp", "intranet", "portal", "web",

            # DevOps and cloud
            "kubernetes", "k8s", "docker", "aws",
            "gcp", "azure", "ci", "cd",

            # Specific services
            "mail", "smtp", "imap", "vpn", "rdp",
            "git", "jenkins", "jira", "confluence",

            # Numeric and version-based
            "dev1", "dev2", "v1", "v2",
            "staging1", "staging2",

            # Additional common subdomains
            "www", "blog", "support", "cdn", "app"
        ]

        # Add variations and combinations
        variations = []
        for base in base_list:
            variations.extend([
                f"{base}-api",
                f"{base}_api",
                f"{base}api",
                f"api-{base}",
                f"api_{base}"
            ])

        return list(set(base_list + variations))

    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """
        Resolve domain to IP addresses using multiple methods

        :param domain: Domain to resolve
        :return: List of unique IP addresses
        """
        ips = set()

        # Try dig resolution
        try:
            dig_cmd = ['dig', '+short', domain]
            dig_result = subprocess.run(
                dig_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Parse IP addresses from dig output
            for line in dig_result.stdout.splitlines():
                line = line.strip()
                try:
                    # Validate IP address
                    ip = ipaddress.ip_address(line)
                    ips.add(str(ip))
                except ValueError:
                    continue
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.debug(f"dig failed for {domain}, falling back to socket")

        # Fallback to socket resolution
        if not ips:
            try:
                socket_results = socket.getaddrinfo(domain, None)
                for result in socket_results:
                    ip = result[4][0]
                    try:
                        # Validate and filter IP addresses
                        validated_ip = ipaddress.ip_address(ip)
                        # Exclude link-local, loopback, and reserved addresses
                        if not (
                            validated_ip.is_loopback or
                            validated_ip.is_link_local or
                            validated_ip.is_reserved
                        ):
                            ips.add(str(validated_ip))
                    except ValueError:
                        continue
            except socket.gaierror:
                self.logger.error(f"Failed to resolve {domain}")

        return list(ips)

    def _content_similarity(self, content1: str, content2: str) -> float:
        """
        Calculate content similarity percentage with advanced cleaning

        :param content1: First content string
        :param content2: Second content string
        :return: Similarity percentage (0-100)
        """
        # Remove HTML tags and normalize whitespace
        def clean_content(content):
            # Remove HTML tags
            content = re.sub(r'<[^>]+>', '', content)
            # Normalize whitespace
            content = re.sub(r'\s+', ' ', content).strip().lower()
            return content

        content1 = clean_content(content1)
        content2 = clean_content(content2)

        # If contents are identical, return 0 similarity
        if content1 == content2:
            return 0.0

        # Basic length-based similarity
        max_len = max(len(content1), len(content2))

        # More nuanced Levenshtein distance
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)

            if len(s2) == 0:
                return len(s1)

            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            return previous_row[-1]

        # Calculate normalized similarity
        distance = levenshtein_distance(content1, content2)
        similarity = (1 - (distance / max_len)) * 100

        return max(0, min(100, similarity))

    def _fetch_url_content(self, url: str, headers: Dict[str, str] = None) -> Optional[str]:
        """
        Fetch content from a URL

        :param url: URL to fetch
        :param headers: Optional headers to send
        :return: Fetched content or None
        """
        try:
            # Prepare curl command
            curl_cmd = [
                'curl',
                '-k',  # Allow insecure connections
                '-s',  # Silent mode
                '-L',  # Follow redirects
                '-m', str(self.timeout)  # Set timeout
            ]

            # Add headers if provided
            if headers:
                for key, value in headers.items():
                    curl_cmd.extend(['-H', f'{key}: {value}'])

            # Add URL
            curl_cmd.append(url)

            # Run curl command
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            return result.stdout

        except Exception as e:
            self.logger.debug(f"Error fetching content: {e}")
            return None

    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform VHost scanning

        :return: List of discovered vhosts
        """
        # Start timing
        self.scan_start_time = time.time()

        # Parse the target URL
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc
        except Exception as e:
            self.logger.error(f"Invalid URL: {e}")
            return []

        # Determine targets (IPs or vhosts)
        try:
            targets = self._resolve_domain_ips(domain) if self.ip_mode else self.wordlist
            self.logger.info(f"Scanning {len(targets)} targets")
        except Exception as e:
            self.logger.error(f"Error determining scan targets: {e}")
            return []

        # Scan modes
        scan_modes = ['default']
        if self.ip_mode:
            scan_modes.extend(['ip_host', 'host_ip'])

        # Comprehensive scanning
        for mode in scan_modes:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Prepare futures for scanning
                futures = {
                    executor.submit(self._scan_target, domain, target, mode): (target, mode)
                    for target in targets
                }

                # Process results
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.results.append(result)

        # End timing
        self.scan_end_time = time.time()

        # Automatically deduplicate results
        deduped_results = []
        seen = set()
        for result in self.results:
            key = (result['hostname'], result.get('similarity', 0), result.get('mode', 'default'))
            if key not in seen:
                seen.add(key)
                deduped_results.append(result)

        self.results = deduped_results

        return self.results

    def _scan_target(self, domain: str, target: str, mode: str = 'default') -> Optional[Dict[str, Any]]:
        """
        Scan a specific target for virtual hosts

        :param domain: Base domain
        :param target: Target vhost or IP
        :param mode: Scanning mode ('default', 'ip_host', 'host_ip')
        :return: Discovered vhost details or None
        """
        try:
            # Determine test hostname and URL based on mode
            if mode == 'default':
                test_hostname = f"{target}.{domain}" if not self.ip_mode else target
                url = f"http://{domain}"
            elif mode == 'ip_host':
                test_hostname = target
                url = f"http://{domain}"
            elif mode == 'host_ip':
                test_hostname = domain
                url = f"http://{target}"
            else:
                return None

            # Fetch default content
            default_content = self._fetch_url_content(url)
            if default_content is None:
                return None

            # Fetch content with modified Host header
            headers = {'Host': test_hostname}
            test_content = self._fetch_url_content(url, headers)
            if test_content is None:
                return None

            # Compare content
            similarity = self._content_similarity(default_content, test_content)

            # Consider it a valid vhost if content is sufficiently different
            SIMILARITY_THRESHOLD = 10  # Lowered from 50 to catch more subtle differences
            if similarity < SIMILARITY_THRESHOLD:
                return {
                    'hostname': test_hostname,
                    'ip_mode': self.ip_mode,
                    'mode': mode,
                    'similarity': round(similarity, 2),
                    'curl_command': f"curl -k -H 'Host: {test_hostname}' {url}"
                }

        except Exception as e:
            self.logger.debug(f"Error scanning {target}: {e}")

        return None

def main():
    # Capture start time for overall script execution
    script_start_time = time.time()

    # Argument parsing
    parser = argparse.ArgumentParser(description='Advanced VHost Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--ip-mode', action='store_true', help='IP-based scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='JSON output file')
    parser.add_argument('--grepable', action='store_true', help='Output in grepable format')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = f'http://{args.url}'

    # Custom wordlist handling
    wordlist = None
    if args.wordlist:
        try:
            if os.path.exists(args.wordlist):
                with open(args.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            else:
                logger.warning(f"Wordlist file '{args.wordlist}' not found. Using default wordlist.")
        except Exception as e:
            logger.error(f"Error reading wordlist: {e}")

    # Interrupt handling
    try:
        # Initialize and run scanner
        scanner = VHostScanner(
            target_url=args.url,
            wordlist=wordlist,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            ip_mode=args.ip_mode
        )

        # Perform scan
        results = scanner.scan()

        # Calculate total scan time
        total_scan_time = time.time() - script_start_time

        # Prepare scan report
        scan_report = {
            'total_targets': len(scanner.wordlist if not args.ip_mode else scanner.wordlist),
            'discovered_hosts': len(results),
            'scan_time_seconds': round(total_scan_time, 2)
        }

        # Output handling
        if args.output:
            try:
                # Combine results and metadata
                output_data = {
                    'scan_info': scan_report,
                    'results': results
                }

                with open(args.output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                print(json.dumps(output_data, indent=2))
                logger.info(f"Results saved to {args.output}")
            except Exception as e:
                logger.error(f"Error saving output: {e}")

        # Display results if not outputting to file
        if not args.output:
            if args.grepable:
                # Grepable output (tab-separated)
                for result in results:
                    print(f"{result['hostname']}\t{result.get('similarity', 0)}\t{result.get('mode', 'default')}\t{result.get('curl_command', 'N/A')}")
            elif args.verbose:
                # Verbose JSON output
                for result in results:
                    print(json.dumps(result, indent=2))
            else:
                # Summary output
                logger.info(f"\nDiscovered {len(results)} potential virtual hosts")
                logger.info(f"Total scan time: {scan_report['scan_time_seconds']} seconds")

                # Summarize results
                summary = {}
                for result in results:
                    hostname = result['hostname']
                    similarity = result.get('similarity', 0)
                    if hostname not in summary:
                        summary[hostname] = {'similarities': [], 'modes': set()}
                    summary[hostname]['similarities'].append(similarity)
                    summary[hostname]['modes'].add(result.get('mode', 'default'))

                print("\nVHost Summary:")
                for hostname, details in summary.items():
                    avg_similarity = sum(details['similarities']) / len(details['similarities'])
                    print(f"  {hostname}: Avg Similarity {avg_similarity:.2f}%, Modes: {', '.join(details['modes'])}")

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user.")
        sys.exit(130)  # Standard exit code for keyboard interrupt

    except Exception as e:
        logger.error(f"Fatal error during scanning: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
