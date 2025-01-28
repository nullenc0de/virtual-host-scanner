# Virtual Host Scanner

A Python tool to enumerate virtual hosts on a web server by sending HTTP requests with different host headers and analyzing the responses.

## Features

- Discovers valid virtual hosts by testing a list of common vhost patterns
- Concurrent scanning with configurable thread count for improved speed
- Identifies interesting responses that may indicate a valid host (e.g. redirects, non-standard status codes)
- Optionally follows redirects to map out path-based routing
- Verbose mode for detailed output and debugging
- Generates cURL commands for each discovered host for easy manual testing

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/virtual-host-scanner.git
   ```

2. Navigate to the project directory:
   ```
   cd virtual-host-scanner
   ```

## Usage

Basic usage:
```
python3 vhost_scanner.py -u http://example.com
```

This will scan `example.com` using the default wordlist and settings.

### Options

- `-u`, `--url`: Target URL (required)
- `-w`, `--wordlist`: Path to a custom wordlist file
- `-t`, `--threads`: Number of concurrent threads (default: 10)
- `--ssl`: Force HTTPS requests
- `-v`, `--verbose`: Enable verbose output
- `-r`, `--redirects`: Follow HTTP redirects

## Example

Scan a target with a custom wordlist and verbose output:
```
python3 vhost_scanner.py -u http://example.com -w /path/to/wordlist.txt -v
```

Scan a target over HTTPS with redirect following enabled:
```
python3 vhost_scanner.py -u https://example.com --ssl -r
```

## Contributing

If you'd like to contribute to the project, please fork the repository and submit a pull request with your changes. Make sure to include a detailed description of your modifications.

Before submitting a pull request, please ensure that your code adheres to the existing style and passes all tests.
