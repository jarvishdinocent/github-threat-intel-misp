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
VERIFY_CERT = False  # Set True if using valid TLS certs

# Search terms on GitHub
KEYWORDS = [
    "ioc", "yara", "api_key", "token", "malware", "leak", "dump", "indicator", "threat",
    "CVE-2025", "hash", "csv"
]

MAX_RESULTS_PER_TERM = 15  # GitHub API limit
MISP_TAGS = ["OSINT", "Feed:GitHub", "Confidence:low", "TLP:WHITE"]

# ---------------- INIT ----------------
# Suppress insecure HTTPS warnings for internal MISP use
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# GitHub API Auth (updated)
auth = Auth.Token(GITHUB_TOKEN)
g = Github(auth=auth)

# MISP API Auth (updated)
misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

# ---------------- IOC EXTRACTOR ----------------
def extract_iocs(text):
    iocs = set()
    iocs.update(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text))  # IP addresses
    iocs.update(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))  # Hashes (MD5/SHA1/SHA256)
    iocs.update(re.findall(r'https?://[^\s\'"]+', text))      # URLs
    iocs.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))  # Emails
    return list(iocs)

# ---------------- MISP DEDUP CHECK ----------------
def is_ioc_unique(ioc):
    try:
        result = misp.search(controller='attributes', value=ioc)
        return not result.get("Attribute")
    except Exception as e:
        print(f"[-] MISP search failed for {ioc}: {e}")
        return False

# ---------------- PUSH TO MISP ----------------
def push_iocs_to_misp(iocs, title):
    if not iocs:
        return
    event = MISPEvent()
    event.info = f"[GitHub Feed] {title}"
    event.distribution = 0
    event.analysis = 2
    event.threat_level_id = 2

    for tag in MISP_TAGS:
        event.add_tag(tag)

    for ioc in iocs:
        try:
            if re.match(r'(?:\d{1,3}\.){3}\d{1,3}', ioc):
                event.add_attribute("ip-dst", ioc)
            elif re.match(r'\b[a-fA-F0-9]{32,64}\b', ioc):
                event.add_attribute("sha256", ioc)
            elif re.match(r'https?://[^\s\'"]+', ioc):
                event.add_attribute("url", ioc)
            elif "@" in ioc:
                event.add_attribute("email-src", ioc)
        except Exception as e:
            print(f"[-] Error adding IOC {ioc}: {e}")

    try:
        misp.add_event(event)
        print(f"[+] Event pushed to MISP: {title} with {len(iocs)} IOCs")
    except Exception as e:
        print(f"[-] Failed to push event: {e}")

# ---------------- MAIN LOOP ----------------
def run_github_feed():
    for keyword in KEYWORDS:
        print(f"\n[*] Searching GitHub for: {keyword}")
        try:
            results = g.search_code(keyword, order='desc')[:MAX_RESULTS_PER_TERM]
            for file in results:
                try:
                    url = file.download_url
                    if not url:
                        continue
                    res = requests.get(url)
                    if res.status_code != 200:
                        continue
                    content = res.text
                    iocs = extract_iocs(content)
                    unique_iocs = [ioc for ioc in iocs if is_ioc_unique(ioc)]
                    if unique_iocs:
                        title = f"{file.repository.full_name}/{file.name}"
                        push_iocs_to_misp(unique_iocs, title)
                    time.sleep(2)  # GitHub rate limit protection
                except Exception as e:
                    print(f"[-] Error processing {file.name}: {e}")
        except Exception as e:
            print(f"[-] GitHub search error: {e}")
        time.sleep(3)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    print("[*] Starting GitHub → MISP Feed Monitor...")
    run_github_feed()
