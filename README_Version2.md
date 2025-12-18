# OpenScan

OpenScan is a small tool to scan hosts with nmap for open ports and service versions, then query public vulnerability sources for known CVEs.

Prerequisites
- nmap installed and available in PATH
- Python 3.8+
- pip install -r requirements.txt

Optional:
- NVD API key (set environment variable `NVD_API_KEY`) for improved NVD queries and higher rate limits.

Installation
1. Clone repo
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run:
   ```
   python -m openscan.openscan example.com
   ```

Notes and caveats
- This tool is for authorized security testing only. Do NOT scan systems you don't own or don't have permission to test.
- Nmap version detection is not perfect — product/version strings may be incomplete. The vulnerability lookup uses free-text queries and public APIs, so false positives and false negatives are possible.
- NVD has rate limits; if you provide an api key via `NVD_API_KEY` environment variable the results will be more reliable.

How it works (high level)
- Run `nmap -sV` and parse the XML output.
- For each open port/service, attempt to look up CVEs for the product+version via NVD (preferred) and CIRCL CVE API.
- Produce a table of services with counts of found CVEs and optionally a JSON report.

If you want:
- Automatic CPE-to-CVE mapping (improved) with NVD parameterized queries.
- Use of Vulners or other commercial CVE DBs (requires API key).
- Output formats: SARIF, CSV, or GitHub-friendly annotations.

If you want me to help create a PR, tell me and I’ll provide the exact git/PR steps you should run (or the gh CLI command) and a suggested PR description.