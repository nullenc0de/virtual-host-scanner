# vhost_scanner.py

A comprehensive virtual host scanner that combines subfinder, dnsx, httpx, and VhostFinder to discover and validate virtual hosts, with automatic path scanning for sensitive endpoints.

## Features

- Automatic subdomain discovery using subfinder
- DNS resolution and IP filtering using dnsx
- Quick vhost support detection using httpx
- Deep vhost scanning with path traversal using VhostFinder
- Built-in list of sensitive paths
- Support for custom path wordlists
- Automatic deduplication of IPs and results
- Verification command generation
- Temporary file cleanup

## Requirements

- Python 3.6+
- subfinder (https://github.com/projectdiscovery/subfinder)
- dnsx (https://github.com/projectdiscovery/dnsx)
- httpx (https://github.com/projectdiscovery/httpx)
- VhostFinder (https://github.com/werneror/vhostfinder)

## Installation

1. Install the required tools:
```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install VhostFinder
git clone https://github.com/werneror/VhostFinder.git
cd VhostFinder
go build
sudo mv VhostFinder /usr/local/bin/
```

2. Download the script:
```bash
wget https://raw.githubusercontent.com/yourusername/vhost_scanner/main/vhost_scanner.py
chmod +x vhost_scanner.py
```

## Usage

### Basic Usage
```bash
python3 vhost_scanner.py -d example.com
```

### Using Custom Files
```bash
python3 vhost_scanner.py -s subdomains.txt -i ips.txt
```

### Using Custom Path Wordlist
```bash
python3 vhost_scanner.py -d example.com -w paths.txt
```

### Disable Path Scanning
```bash
python3 vhost_scanner.py -d example.com --no-path-scan
```

### Verbose Output
```bash
python3 vhost_scanner.py -d example.com -v
```

## Command Line Arguments

```
-d, --domain        Domain to scan (optional if using custom lists)
-s, --subdomains    File containing list of subdomains
-i, --ips          File containing list of IP addresses
-w, --wordlist     Optional: Custom wordlist for path scanning
--no-path-scan     Disable path scanning
-v, --verbose      Show verbose output
```

## Built-in Path Scanning

The tool includes a curated list of sensitive paths to check, including:
- Admin panels
- API endpoints
- Authentication endpoints
- Development resources
- Common applications
- Sensitive files
- Configuration files

## Output Format

The tool provides detailed output including:
- Discovered vhost-supporting domains and IPs
- Path scan results
- Status codes and content lengths
- Verification commands for manual testing

Example output:
```
[+] Found 3 domains supporting vhost:
  - admin.example.com
  - api.example.com
  - dev.example.com

[+] Actionable Virtual Hosts Found:
--------------------------------------------------------------------------------
IP: 192.168.1.1
  Host: admin.example.com
  Path: /admin
  Status: 200
  Content Length: 1234

  Verification command:
  curl -sSik -H 'Host: admin.example.com' 'https://192.168.1.1/admin' -o /dev/null -w 'Status: %{http_code}, Length: %{size_download}\n'
```

## Error Handling

The script includes comprehensive error handling:
- Validates required tools are installed
- Checks input file existence and readability
- Handles network timeouts and connection errors
- Provides debug output with -v flag

## Temporary Files

The script automatically creates and cleans up temporary files used during scanning. These files are stored in the system's temporary directory and are removed when the script exits.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Ensure you have permission to scan the target systems before using this tool.
