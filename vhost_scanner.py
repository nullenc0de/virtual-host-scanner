#!/usr/bin/env python3
import subprocess
import sys
import re
import os
import tempfile
import atexit
from typing import List, Dict, Set, Optional, Tuple
import argparse
from dataclasses import dataclass
from collections import defaultdict

print("[DEBUG] Script starting...")  # Initial debug print

# Global list to track temporary files
temp_files = []

def cleanup_temp_files():
    """Clean up temporary files on script exit."""
    for file_path in temp_files:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"[-] Error cleaning up {file_path}: {e}")

def create_temp_file(prefix='vhost_') -> str:
    """Create a temporary file and register it for cleanup."""
    temp = tempfile.NamedTemporaryFile(prefix=prefix, delete=False)
    temp_path = temp.name
    temp.close()
    temp_files.append(temp_path)
    return temp_path

# Register cleanup function
atexit.register(cleanup_temp_files)

@dataclass
class VhostResult:
    ip: str
    host: str
    path: str
    status_code: int
    content_length: int
    is_different: bool
    error_message: str = ""

def read_file_lines(filepath: str) -> List[str]:
    """Read lines from file and return as list."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Error reading file {filepath}: {e}")
        return []

def run_subfinder_and_dnsx(domain: str) -> tuple[str, str]:
    """Run subfinder and dnsx commands and return temporary file paths with optimizations."""
    print("[DEBUG] Starting subfinder and dnsx...")  # Debug print
    subs_file = create_temp_file('subs_')
    dns_file = create_temp_file('dns_')
    unique_ips_file = create_temp_file('unique_ips_')
    
    print(f"[DEBUG] Created temp files: {subs_file}, {dns_file}, {unique_ips_file}")  # Debug print
    
    # Run subfinder with optimized settings
    print("[+] Running subfinder (this might take a minute)...")
    subprocess.run([
        'subfinder', 
        '-d', domain, 
        '-o', subs_file,
        '-t', '50',  # Increase threads
        '-timeout', '5'  # Reduce timeout
    ], check=True)
    
    # Run dnsx with optimizations
    print("[+] Running dnsx and filtering unique IPs...")
    subprocess.run([
        'dnsx',
        '-l', subs_file,
        '-resp-only',
        '-retry', '2',  # Reduce retries
        '-t', '50',     # Increase threads
        '-o', dns_file
    ], check=True)
    
    # Filter unique IPs
    seen_ips = set()
    with open(dns_file, 'r') as f, open(unique_ips_file, 'w') as out:
        for line in f:
            ip = line.strip()
            if ip not in seen_ips:
                seen_ips.add(ip)
                out.write(f"{ip}\n")
    
    return subs_file, unique_ips_file

def check_vhost_support(domains: List[str], ips: List[str]) -> tuple[List[str], List[str]]:
    """Use httpx to quickly identify hosts and IPs that support vhosts."""
    supported_hosts = []
    supported_ips = []
    
    try:
        # Check domains
        if domains:
            print("[+] Checking domains for vhost support...")
            domains_file = create_temp_file('domains_')
            with open(domains_file, 'w') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            
            cmd = ['httpx', '-l', domains_file, '-silent', '-vhost']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in process.stdout.splitlines():
                if '[vhost]' in line:
                    host = line.split()[0]
                    supported_hosts.append(host.replace('https://', '').replace('http://', ''))
        
        # Check IPs
        if ips:
            print("[+] Checking IPs for vhost support...")
            ips_file = create_temp_file('ips_')
            with open(ips_file, 'w') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            
            cmd = ['httpx', '-l', ips_file, '-silent', '-vhost']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in process.stdout.splitlines():
                if '[vhost]' in line:
                    ip = line.split()[0]
                    ip = ip.replace('https://', '').replace('http://', '')
                    supported_ips.append(ip)
        
        return supported_hosts, supported_ips
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running httpx: {e}")
        return [], []
    except Exception as e:
        print(f"[-] Unexpected error checking vhosts: {e}")
        return [], []

def get_sensitive_paths() -> List[str]:
    """Returns a prioritized list of sensitive paths to check."""
    return [
        # Critical Admin Paths
        '/admin',
        '/.git',
        '/wp-admin',
        '/administrator',
        '/admins',
        '/Admin',
        '/adminpanel',
        '/admin-console',
        '/manager',
        
        # Common API Endpoints
        '/api',
        '/api/v1',
        '/graphql',
        '/swagger',
        '/swagger-ui',
        
        # Authentication
        '/login',
        '/auth',
        '/authorize',
        
        # Development
        '/.env',
        '/debug',
        '/dev',
        
        # Common Applications
        '/jenkins',
        '/jira',
        '/gitlab',
        
        # Sensitive Areas
        '/backup',
        '/config',
        '/internal'
    ]

def generate_curl_command(result: VhostResult) -> str:
    """Generate a curl command to verify the finding."""
    return (f"curl -sSik -H 'Host: {result.host}' 'https://{result.ip}{result.path}' "
            f"-o /dev/null -w 'Status: %{{http_code}}, Length: %{{size_download}}\\n'")

def parse_vhostfinder_output(output: str) -> List[VhostResult]:
    """Parse VhostFinder output and return structured results."""
    results = []
    
    # Regular expressions for matching different output lines
    error_pattern = r'\[!\] \[([0-9.]+)\] \[([^]]+)\] \[([0-9]+)\] \[([0-9]+)\] ([^ ]+) -> (.+)'
    result_pattern = r'\[-\] \[([0-9.]+)\] \[([^]]+)\] \[([0-9]+)\] \[([0-9-]+)\] ([^ ]+)(?: is different than the baseline(?:, but is not different than public facing domain)?)?'
    
    for line in output.splitlines():
        # Skip baseline and informational messages
        if '[!] Finding vhosts!' in line or '[!] Obtaining baseline' in line:
            continue
            
        # Parse error lines (typically timeout or connection errors)
        error_match = re.match(error_pattern, line)
        if error_match:
            ip, path, status, length, host, error = error_match.groups()
            results.append(VhostResult(
                ip=ip,
                host=host,
                path=path,
                status_code=int(status),
                content_length=int(length),
                is_different=False,
                error_message=error
            ))
            continue
        
        # Parse result lines
        result_match = re.match(result_pattern, line)
        if result_match:
            ip, path, status, length, host = result_match.groups()[:5]
            is_different = 'is different than the baseline' in line
            results.append(VhostResult(
                ip=ip,
                host=host,
                path=path,
                status_code=int(status),
                content_length=int(length) if length != '-1' else -1,
                is_different=is_different,
                error_message=""
            ))
    
    return results

def filter_actionable_vhosts(results: List[VhostResult]) -> List[VhostResult]:
    """Filter results to show only actionable vhosts with unique responses."""
    actionable = []
    
    # Group results by IP address
    ip_groups = defaultdict(list)
    for result in results:
        ip_groups[result.ip].append(result)
    
    for ip, ip_results in ip_groups.items():
        # Find successful responses (status 200-299 or 300-399)
        successful = [r for r in ip_results if 200 <= r.status_code < 400]
        
        # Find responses with different content
        different = [r for r in successful if r.is_different]
        
        # Filter out common redirects and empty responses
        interesting = [r for r in different if not (
            # Filter out common redirect lengths
            (r.status_code in [301, 302] and r.content_length in [0, 3, 162, -1]) or
            # Filter out empty responses
            r.content_length == 0 or
            # Filter out typical error page lengths
            r.content_length in [-1, 3]
        )]
        
        actionable.extend(interesting)
    
    return actionable

def main():
    print("[DEBUG] Main function started")  # Debug print
    
    parser = argparse.ArgumentParser(description='Wrapper for VhostFinder to identify actionable virtual hosts')
    
    # Make domain optional if custom lists are provided
    parser.add_argument('-d', '--domain', help='Domain to scan (optional if using custom lists)')
    parser.add_argument('-s', '--subdomains', help='File containing list of subdomains')
    parser.add_argument('-i', '--ips', help='File containing list of IP addresses')
    parser.add_argument('-w', '--wordlist', help='Optional: Custom wordlist for path scanning')
    parser.add_argument('--no-path-scan', action='store_true', help='Disable path scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    
    args = parser.parse_args()
    print(f"[DEBUG] Args parsed: {args}")  # Debug print
    
    try:
        # Validate inputs
        if not args.domain and not (args.subdomains and args.ips):
            parser.error("Either -d/--domain or both -s/--subdomains and -i/--ips must be provided")
            
        subs_file = ""
        dns_file = ""
        
        if args.domain:
            # Run subfinder and dnsx
            print(f"[+] Running asset discovery for {args.domain}")
            subs_file, dns_file = run_subfinder_and_dnsx(args.domain)
        else:
            # Use provided files
            subs_file = args.subdomains
            dns_file = args.ips
            
        # Read domains and IPs
        domains = read_file_lines(subs_file)
        ips = read_file_lines(dns_file)
        
        print(f"[DEBUG] Found {len(domains)} domains and {len(ips)} IPs")  # Debug print
        
        # Check both domains and IPs for vhost support
        vhost_domains, vhost_ips = check_vhost_support(domains, ips)
        
        if not vhost_domains and not vhost_ips:
            print("[-] No hosts or IPs supporting vhost found.")
            return
            
        # Report findings
        if vhost_domains:
            print(f"\n[+] Found {len(vhost_domains)} domains supporting vhost:")
            for host in vhost_domains:
                print(f"  - {host}")
                
        if vhost_ips:
            print(f"\n[+] Found {len(vhost_ips)} IPs supporting vhost:")
            for ip in vhost_ips:
                print(f"  - {ip}")
            
        # Write vhost-supported domains and IPs to file
        vhost_file = create_temp_file('vhost_targets_')
        with open(vhost_file, 'w') as f:
            for domain in vhost_domains:
                f.write(f"{domain}\n")
            # Add IPs to the list as well
            for ip in vhost_ips:
                f.write(f"{ip}\n")
            
        # Get sensitive paths
        paths = []
        if not args.no_path_scan:
            if args.wordlist and os.path.isfile(args.wordlist):
                with open(args.wordlist, 'r') as f:
                    paths = [line.strip() for line in f if line.strip()]
                print(f"[+] Using {len(paths)} paths from wordlist")
            else:
                paths = get_sensitive_paths()
                print(f"[+] Using {len(paths)} built-in sensitive paths")
        
        # Run VhostFinder with optimizations
        print("[+] Running VhostFinder with optimized settings...")
        
        # Base command with aggressive timeouts and increased threads
        cmd = [
            'VhostFinder',
            '-ips', dns_file,
            '-wordlist', vhost_file,  # Use file with only vhost-supported domains
            '-v',
            '-verify',
            '-force',
            '-t', '50',  # Aggressive threading
            '-timeout', '3'  # Short timeout
        ]
        
        # Add high-priority paths if enabled
        if paths:
            print(f"[+] Scanning with {len(paths)} paths...")
            cmd.extend(['-p'] + paths)
        
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            print(f"[-] VhostFinder failed with error: {process.stderr}")
            sys.exit(1)
        
        # Parse and filter results
        print("\n[+] Analyzing responses...")
        results = parse_vhostfinder_output(process.stdout)
        actionable = filter_actionable_vhosts(results)
        
        # Display results
        print("\n[+] Actionable Virtual Hosts Found:")
        print("-" * 80)
        
        if not actionable:
            print("No actionable virtual hosts found.")
            return
        
        # Group by IP for better visualization
        ip_groups = defaultdict(list)
        for result in actionable:
            ip_groups[result.ip].append(result)
        
        for ip, ip_results in ip_groups.items():
            print(f"\nIP: {ip}")
            for result in ip_results:
                print(f"  Host: {result.host}")
                print(f"  Path: {result.path}")
                print(f"  Status: {result.status_code}")
                print(f"  Content Length: {result.content_length}")
                print("\n  Verification command:")
                print(f"  {generate_curl_command(result)}")
                print("  " + "-" * 40)
        
        # If verbose, show error messages too
        if args.verbose:
            print("\n[+] Errors and Warnings:")
            for result in results:
                if result.error_message:
                    print(f"  {result.host} -> {result.error_message}")
    
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running command: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        print(f"[DEBUG] Error type: {type(e)}")  # Debug print
        import traceback
        traceback.print_exc()  # Print full traceback for debugging
        sys.exit(1)

if __name__ == "__main__":
    main()
