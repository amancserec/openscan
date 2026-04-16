#!/usr/bin/env python3
"""
OpenScan - simple website/host port + service scanner with CVE lookup.

Usage:
    python -m openscan.openscan TARGET [--output report.json] [--nmap-args "-p80,443"]
Examples:
    python -m openscan.openscan 192.0.2.1
    python -m openscan.openscan example.com --nmap-args "-p1-1024" --output result.json
Notes:
- Requires nmap binary installed and accessible in PATH.
- For better NVD results, set environment variable NVD_API_KEY with your NVD API key.
"""

import os
import sys
import argparse
import subprocess
import json
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import requests
from defusedxml import ElementTree as ET
from tabulate import tabulate
from dateutil import parser as dateparser

# Constants
CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

NVD_API_KEY_ENV = "NVD_API_KEY"

def run_nmap(target: str, extra_args: str = "-sV -p- --min-rate 1000") -> str:
    """
    Run nmap and return XML stdout.
    Uses -oX - to write XML to stdout.
    """
    cmd = ["nmap"]
    # ensure -sV is present
    args = ["-sV", "-oX", "-"]
    if extra_args:
        # allow user to override ports or other args but keep -sV and -oX -
        custom_args = extra_args.strip().split()
        # ensure -sV present
        if "-sV" not in custom_args:
            custom_args.insert(0, "-sV")
        args = custom_args + ["-oX", "-"]
    cmd += args + [target]
    print(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print("nmap failed:", proc.stderr, file=sys.stderr)
        raise SystemExit(1)
    return proc.stdout

def parse_nmap_xml(xml_data: str) -> List[Dict[str, Any]]:
    """
    Parse nmap XML output and return list of services with host, port, product, version, cpe.
    """
    root = ET.fromstring(xml_data)
    results = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None
        # hostname if present
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            try:
                parsed_port = int(portid) if portid is not None else None
            except ValueError:
                parsed_port = None
            service_el = port.find("service")
            service = {
                "host": ip,
                "hostname": hostname,
                "port": parsed_port,
                "protocol": protocol,
                "state": state,
                "name": None,
                "product": None,
                "version": None,
                "extrainfo": None,
                "cpe": []
            }
            if service_el is not None:
                service["name"] = service_el.get("name")
                service["product"] = service_el.get("product")
                service["version"] = service_el.get("version")
                service["extrainfo"] = service_el.get("extrainfo")
                # cpe entries
                for cpe in service_el.findall("cpe"):
                    if cpe.text:
                        service["cpe"].append(cpe.text)
            results.append(service)
    return results

def query_nvd(keyword: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Query NVD by keyword (product + version). Requires API key to avoid strict rate limits.
    Returns list of CVE dicts.
    """
    params = {"keyword": keyword}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        items = data.get("result", {}).get("CVE_Items", []) or data.get("CVE_Items", [])
        cves = []
        for it in items:
            cve_id = it.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            descs = it.get("cve", {}).get("description", {}).get("description_data", [])
            desc = descs[0].get("value") if descs else ""
            impact = it.get("impact", {})
            score = None
            if "baseMetricV3" in impact:
                score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
            elif "baseMetricV2" in impact:
                score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore")
            refs = []
            for rref in it.get("cve", {}).get("references", {}).get("reference_data", []):
                refs.append(rref.get("url"))
            cves.append({"id": cve_id, "summary": desc, "cvss": score, "refs": refs})
        return cves
    except Exception as e:
        print("NVD query failed:", e, file=sys.stderr)
        return []

def query_circl(query: str) -> List[Dict[str, Any]]:
    """
    Query CIRCL CVE public API by free-text search.
    Note: CIRCL endpoint: https://cve.circl.lu/api/search/{query}
    """
    try:
        url = urljoin(CIRCL_SEARCH_URL, requests.utils.requote_uri(query))
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = []
        # data is list of CVE dicts
        for item in data:
            cve_id = item.get("id")
            summary = item.get("summary")
            refs = item.get("references", [])
            # CIRCL may include cvss scores
            cvss = item.get("cvss")
            results.append({"id": cve_id, "summary": summary, "cvss": cvss, "refs": refs})
        return results
    except Exception as e:
        print("CIRCL query failed:", e, file=sys.stderr)
        return []

def lookup_vulns_for_service(product: Optional[str], version: Optional[str], cpes: List[str]) -> List[Dict[str, Any]]:
    """
    Given product and version strings and cpes, return list of CVEs from available sources.
    Strategy:
      - If CPE present, try NVD with cpeSearch or keyword
      - Else try NVD with "product version"
      - Fallback to CIRCL search on product version
    """
    api_key = os.getenv(NVD_API_KEY_ENV)
    keywords = []
    if product and version:
        keywords.append(f"{product} {version}")
    if product:
        keywords.append(product)
    # include cpe entries as keywords
    for c in cpes:
        keywords.append(c)

    aggregated = {}
    for kw in keywords:
        # try NVD if API key provided (or even without, but that may be rate limited)
        if api_key:
            items = query_nvd(kw, api_key=api_key)
            for it in items:
                aggregated[it["id"]] = it
        else:
            # try NVD anyway but without key (best-effort)
            items = query_nvd(kw, api_key=None)
            for it in items:
                aggregated[it["id"]] = it
        # fallback to CIRCL if nothing yet for this keyword
        if not aggregated:
            items = query_circl(kw)
            for it in items:
                aggregated[it["id"]] = it
        # lighten rate to be polite
        time.sleep(0.6)
    return list(aggregated.values())

def format_results(services: List[Dict[str, Any]], report_json: Optional[str] = None):
    """
    Print table and optionally dump JSON report.
    """
    rows = []
    full = []
    for s in services:
        vulns = s.get("vulns", [])
        vuln_count = len(vulns)
        highest_cvss = None
        for v in vulns:
            try:
                if v.get("cvss") is not None:
                    score = float(v.get("cvss"))
                    if highest_cvss is None or score > highest_cvss:
                        highest_cvss = score
            except Exception:
                pass
        rows.append([
            s.get("host"),
            s.get("port"),
            s.get("name") or "",
            s.get("product") or "",
            s.get("version") or "",
            vuln_count,
            highest_cvss if highest_cvss is not None else ""
        ])
        full.append(s)
    headers = ["host", "port", "service", "product", "version", "vulns", "max CVSS"]
    print(tabulate(rows, headers=headers, tablefmt="github"))
    if report_json:
        with open(report_json, "w") as fh:
            json.dump({"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": full}, fh, indent=2)
        print(f"Saved JSON report to {report_json}")

def main(argv):
    parser = argparse.ArgumentParser(description="OpenScan - nmap + CVE lookup")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("--nmap-args", help="Extra nmap args (example: \"-p80,443 -sV\")", default="-sV -p1-65535")
    parser.add_argument("--output", help="Write JSON output to file", default=None)
    parser.add_argument("--single-port", help="Scan only a single port (override nmap args)", type=int, default=None)
    args = parser.parse_args(argv)

    extra = args.nmap_args
    if args.single_port:
        extra = f"-sV -p{args.single_port}"
    xml = run_nmap(args.target, extra_args=extra)
    services = parse_nmap_xml(xml)
    print(f"Discovered {len(services)} service entries (including closed/unfiltered). Filtering by state='open'...")
    open_services = [s for s in services if s.get("state") == "open"]
    print(f"{len(open_services)} open service(s) will be checked for vulnerabilities.")
    for s in open_services:
        print(f"Looking up vulns for {s.get('host')}:{s.get('port')} -> {s.get('product') or s.get('name')} {s.get('version')}")
        vulns = lookup_vulns_for_service(s.get("product"), s.get("version"), s.get("cpe", []))
        s["vulns"] = vulns
    format_results(open_services, report_json=args.output)

if __name__ == "__main__":
    main(sys.argv[1:])
