# ReconForge

ReconForge is a professional, open-source reconnaissance and attack-surface intelligence tool built for authorized security testing, defensive security work, and cyber education.

## Legal notice

ReconForge is intended only for systems the user owns or has explicit written permission to assess. It is not designed for credential theft, malware, persistence, evasion, or unauthorized access.

## Features

- Target validation for domains, URLs, IPv4, and IPv6
- DNS reconnaissance with A, AAAA, MX, NS, TXT, CNAME, and SOA record collection
- Safe Nmap-based port scanning using argument arrays and subprocess execution
- HTTP and HTTPS reconnaissance with security header checks
- TLS metadata inspection for HTTPS endpoints
- Passive subdomain discovery using conservative DNS lookups and optional user wordlists
- Risk scoring and high-level attack-surface summary
- SQLite-backed scan history and comparison
- HTML, JSON, and Markdown reporting
- Rich terminal output for beginners and professionals

## Example terminal output

```text
╔══════════════════════════════════════╗
║          RECONFORGE v0.1.0          ║
╚══════════════════════════════════════╝

Target: example.com
[+] Target validated
[+] Scan authorized target only
[+] DNS complete
[+] Port scan complete
[+] Web scan complete
Risk Score: MEDIUM
Scan ID: 42
```

## Installation on Kali Linux

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap

git clone https://github.com/your-user/reconforge.git
cd reconforge
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
reconforge --help
reconforge scan example.com
reconforge scan example.com --full
reconforge dns example.com
reconforge ports example.com
reconforge web https://example.com
reconforge subdomains example.com --wordlist wordlists/common.txt
reconforge report 1 --format html
reconforge history
reconforge compare 1 2
```

## Architecture

ReconForge is organized into a small set of focused modules:

- reconforge/cli.py: CLI and command dispatch
- reconforge/scanner.py: orchestration of scan workflows
- reconforge/database.py: SQLite persistence layer
- reconforge/modules/: domain, port, web, TLS, and subdomain checks
- reconforge/intelligence/: scoring and delta comparison
- reconforge/reports/: HTML, JSON, and Markdown export
- reconforge/utils/: validation, logging, and output helpers

## Supported modules

- DNS reconnaissance
- WHOIS lookup (graceful fallback when absent)
- Nmap port scanning
- HTTP/HTTPS web checks
- TLS inspection
- Passive subdomain discovery
- Technology heuristics
- Reporting and scan comparison

## Database explanation

SQLite stores scan metadata and results in a straightforward schema:

- scans
- targets
- dns_records
- ports
- web_results
- subdomains
- technologies
- findings

This keeps the project lightweight while still supporting history and comparison.

## Reporting

Reports can be generated in multiple formats:

```bash
reconforge report 1 --format html
reconforge report 1 --format json
reconforge report 1 --format markdown
```

## Testing

```bash
pytest -q
```

## Troubleshooting

- If Nmap is missing: sudo apt install nmap
- If WHOIS is missing: the tool will warn and continue safely
- If a target is malformed: validation fails without scanning
- If a URL is unavailable: web checks return a useful message rather than crashing

## Roadmap

- Improved certificate parsing and TLS risk logic
- Additional passive data sources and better heuristics
- Better HTML executive summaries and templates
- CI automation and release packaging
- Additional scan diffing and trend analysis

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add or update tests
4. Run pytest and verify the CLI still works
5. Submit a pull request with a clear summary

## License

This project is licensed under the MIT License. See the LICENSE file for details.
