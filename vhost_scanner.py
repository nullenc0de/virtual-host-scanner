#!/usr/bin/env python3

import argparse
import concurrent.futures
import requests
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_wordlist():
    """Generate a list of common vhost names."""
    return [
        "dev", "development", "staging", "stage", "prod", "production",
        "test", "testing", "qa", "uat", "demo", "admin", "api",
        "internal", "backend", "private", "secure", "corp", "intranet",
        "git", "jenkins", "build", "ci", "jira", "confluence", "wiki",  
        "portal", "dev-api", "stage-api", "test-api", "v1", "v2",
        # Cloud and DevOps
        "kubernetes", "k8s", "docker", "aws", "gcp", "azure",
        # Additional services
        "mail", "smtp", "imap", "pop", "vpn", "rdp", "ftp", "sftp",
        # Development
        "dev1", "dev2", "staging1", "staging2", "preview", "sandbox",
        # Infrastructure 
        "proxy", "gateway", "lb", "loadbalancer", "cdn", "cache",
        # Tools
        "kibana", "grafana", "prometheus", "sonar", "nexus", "registry",
        # Auth and Security
        "auth", "login", "sso", "identity", "accounts", "oauth",
    ]

def check_vhost(base_url, vhost, ssl, baseline_resp, follow_redirects, verbose):
    """Check a single vhost for validity."""
    parsed_url = urlparse(base_url)
    domain = parsed_url.netloc
    protocol = 'https' if ssl else 'http'
    
    # Create test URL and hostname
    test_hostname = f"{vhost}.{domain}"
    url = f"{protocol}://{domain}"
    
    try:
        # Test request with vhost
        resp = requests.get(
            url,
            headers={'Host': test_hostname},
            verify=False,
            timeout=5,
            allow_redirects=follow_redirects
        )
        
        # Check for likely favourable response characteristics
        if 300 <= resp.status_code < 400:
            location = resp.headers.get('Location', '')
            
            if location.startswith(f"{protocol}://{test_hostname}"):
                access = f"curl -k -H 'Host: {test_hostname}' {url}"
                if follow_redirects:
                    access += f" #Redirects to {location}"
                
                if not baseline_resp or resp.status_code != baseline_resp.status_code:
                    result = f"{test_hostname} - Status: {resp.status_code} - Length: {len(resp.text)} - Server: {resp.headers.get('Server', 'Unknown')}\n  {access}"

                    return result if not verbose else f"[Potential Valid Host] {result}"
                elif verbose:
                    return f"[Excluded Similar Response] {test_hostname} - Status: {resp.status_code}"

            elif verbose:
                return f"[Excluded Generic Redirect] {test_hostname} - Redirects to {location}"
        
        elif resp.status_code not in (baseline_resp.status_code, 404, 400, 403) if baseline_resp else resp.status_code not in (404, 400, 403):
            if verbose:
                result = f"{test_hostname} - Status: {resp.status_code} - Length: {len(resp.text)} - Server: {resp.headers.get('Server', 'Unknown')}"
                return f"[Interesting Response] {result}"
        
        elif verbose:
            return f"[Common Status Code] {test_hostname} - {resp.status_code}"
            
    except requests.exceptions.RequestException as e:
        if verbose:
            return f"[Error] Failed to connect to {test_hostname}: {str(e)}"
    
    return None

def main():
    parser = argparse.ArgumentParser(description='Virtual Host Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--ssl', action='store_true', help='Force HTTPS')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all results including errors and common responses')
    parser.add_argument('-r', '--redirects', action='store_true', help='Follow HTTP redirects')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"\nScanning {args.url}...")
    
    # Load or generate wordlist
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                vhosts = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Wordlist file '{args.wordlist}' not found", file=sys.stderr)
            sys.exit(1)
    else:
        vhosts = generate_wordlist()

    # Get baseline response for comparison
    baseline_resp = None  
    try:
        baseline_resp = requests.get(
            args.url,
            verify=False,
            timeout=5,
            allow_redirects=args.redirects
        )
        if args.verbose:
            print(f"Baseline: {baseline_resp.status_code} / {len(baseline_resp.text)} bytes / {baseline_resp.headers.get('Server', '')}\n")
    except requests.exceptions.RequestException as e:
        if args.verbose:
            print(f"Warning: Failed to get baseline response - {str(e)}\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_vhost = {
            executor.submit(check_vhost, args.url, vhost, args.ssl, baseline_resp, args.redirects, args.verbose): vhost 
            for vhost in vhosts
        }
        
        found = False
        for future in concurrent.futures.as_completed(future_to_vhost):
            result = future.result()
            if result:
                found = True
                print(result)
                
        if not found:
            if args.verbose:
                print("No virtual hosts discovered.\n") 
            else:
                print("No likely virtual hosts found. For more details, use the -v option.\n")
            
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
