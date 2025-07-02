# Website Security Scanner

A comprehensive Python-based web security scanner for penetration testers, bug bounty hunters, and sysadmins.  
It performs port scanning, security header analysis, technology fingerprinting, common file exposure checks, basic vulnerability fuzzing, SSL/TLS checks, cookie security analysis, and generates a detailed HTML report for each target.

---

## Features

- **Domain-based output folders** for organized results
- **Port scanning** (Nmap or socket fallback)
- **Security header analysis**
- **Technology & CMS fingerprinting**
- **Common file exposure checks** (`robots.txt`, `.env`, `.git/config`, etc.)
- **Basic vulnerability fuzzing** (XSS, SQLi, LFI on forms and URL params)
- **SSL/TLS certificate and cipher checks**
- **Cookie security flag analysis**
- **CVE lookup** for detected technologies (via NVD API)
- **Detailed HTML reporting**

---

## Requirements

- Python 3.6+
- [nmap](https://nmap.org/) (optional, for advanced port scanning)
- Python packages: `requests`

Install dependencies:
```bash
pip install -r requirements.txt
```

**requirements.txt**
```
requests
```

---

## Usage

```bash
python3 website_security_scanner.py --target https://example.com
```

You will be prompted whether to scan all ports with nmap (`-p-`).  
Reports and scan results are saved in `clients/<domain>/`.

---

## Output

- **HTML Report:** `clients/<domain>/security_report_<domain>.html`
- **Port Scan Results:** `clients/<domain>/port_scan.txt`
- **Homepage HTML:** `clients/<domain>/homepage.html`

---

## Notes

- For best results, run as a user with network scan permissions.
- Nmap is optional but recommended for full port scanning.
- The scanner is for **educational and authorized testing only**.  
  **Do not scan targets without permission.**

---

## Disclaimer

This tool is provided for educational and authorized security testing purposes only.  
The author is not responsible for misuse or damage caused by this tool.

---

## License

MIT License

---

## Author

Adam Daradkeh
