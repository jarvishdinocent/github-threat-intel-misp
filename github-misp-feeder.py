#!/usr/bin/env python3

import re
import time
import requests
import urllib3
from github import Github, Auth
from pymisp import PyMISP, MISPEvent

# ---------------- CONFIGURATION ----------------
GITHUB_TOKEN = "your_github_token_here"
MISP_URL = "https://your.misp.instance"
MISP_KEY = "your_misp_api_key_here"
VERIFY_CERT = False

KEYWORDS = [
    "ioc", "yara", "api_key", "token", "malware", "leak",
    "dump", "indicator", "threat", "CVE-2025", "hash", "csv"
]

MAX_RESULTS_PER_TERM = 15
MISP_TAGS = ["osint", "source:github", "tlp:white"]

# ---------------- INIT ----------------
urllib3.disable_warnings()

auth = Auth.Token(GITHUB_TOKEN)
g = Github(auth=auth)

misp = PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_CERT)

# ---------------- LOAD EXISTING IOCS ----------------
def load_existing_iocs():
    print("[*] Loading existing IOCs from MISP (for dedup)...")
    existing = set()
    try:
        results = misp.search(controller='attributes', limit=5000)
        for attr in results.get("Attribute", []):
            existing.add(attr["value"])
    except Exception as e:
        print(f"[-] Failed to load existing IOCs: {e}")
    print(f"[+] Loaded {len(existing)} existing IOCs")
    return existing

# ---------------- IOC EXTRACTOR ----------------
def extract_iocs(text):
    iocs = set()

    iocs.update(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text))  # IP
    iocs.update(re.findall(r'\b[a-fA-F0-9]{64}\b', text))      # SHA256
    iocs.update(re.findall(r'\b[a-fA-F0-9]{40}\b', text))      # SHA1
    iocs.update(re.findall(r'\b[a-fA-F0-9]{32}\b', text))      # MD5
    iocs.update(re.findall(r'https?://[^\s\'"]+', text))       # URL
    iocs.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))  # Email

    return list(iocs)

# ---------------- IOC TYPE DETECTION ----------------
def get_ioc_type(ioc):
    if re.match(r'(?:\d{1,3}\.){3}\d{1,3}', ioc):
        return "ip-dst"
    elif re.match(r'\b[a-fA-F0-9]{64}\b', ioc):
        return "sha256"
    elif re.match(r'\b[a-fA-F0-9]{40}\b', ioc):
        return "sha1"
    elif re.match(r'\b[a-fA-F0-9]{32}\b', ioc):
        return "md5"
    elif re.match(r'https?://', ioc):
        return "url"
    elif "@" in ioc:
        return "email-src"
    return None

# ---------------- PUSH TO MISP ----------------
def push_iocs_to_misp(iocs, title):
    if not iocs:
        print(f"[SKIPPED] No new IOCs for {title}")
        return

    event = MISPEvent()
    event.info = f"[GitHub] {title}"
    event.distribution = 3
    event.analysis = 2
    event.threat_level_id = 2

    for tag in MISP_TAGS:
        event.add_tag(tag)

    for ioc in iocs:
        ioc_type = get_ioc_type(ioc)
        if ioc_type:
            event.add_attribute(ioc_type, ioc, comment="Extracted from GitHub")

    try:
        event = misp.add_event(event, pythonify=True)
        print(f"[+] Event created: {event.id} with {len(iocs)} new IOCs")
    except Exception as e:
        print(f"[-] Failed to push event: {e}")

# ---------------- MAIN LOOP ----------------
def run_github_feed():
    existing_iocs = load_existing_iocs()

    for keyword in KEYWORDS:
        print(f"\n[*] Searching GitHub for: {keyword}")

        try:
            results = g.search_code(keyword, order='desc')[:MAX_RESULTS_PER_TERM]

            for file in results:
                try:
                    url = file.download_url
                    if not url:
                        continue

                    res = requests.get(url, timeout=15)
                    if res.status_code != 200:
                        continue

                    content = res.text
                    extracted = extract_iocs(content)

                    # ---------------- DEDUP ----------------
                    new_iocs = []
                    for ioc in extracted:
                        if ioc not in existing_iocs:
                            existing_iocs.add(ioc)
                            new_iocs.append(ioc)

                    if new_iocs:
                        title = f"{file.repository.full_name}/{file.name}"
                        push_iocs_to_misp(new_iocs, title)

                    time.sleep(2)

                except Exception as e:
                    print(f"[-] File error: {file.name} → {e}")

        except Exception as e:
            print(f"[-] GitHub search error: {e}")

        time.sleep(3)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    print("[*] Starting GitHub → MISP Feed Monitor with Dedup...")
    run_github_feed()
