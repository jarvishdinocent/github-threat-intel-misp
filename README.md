# GitHub → MISP IOC Feeder

A Python script that monitors **GitHub repositories** for potential **IOC leaks, malware dumps, and token exposures**, then ingests unique indicators into **MISP**.  
If your SOC uses the **MISP → OpenCTI connector**, all indicators flow automatically into **OpenCTI** as well.

---

## ✨ Features
- Searches GitHub for security-related keywords (`ioc`, `yara`, `token`, `malware`, etc.)
- Extracts IOCs using regex (IPs, hashes, URLs, emails)
- Deduplicates against existing MISP attributes (no duplicates)
- Tags IOCs with TLP and source info (`OSINT`, `Feed:GitHub`)
- Supports SOC pipelines via MISP → OpenCTI connector

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/jarvishdinocent/github-misp-feeder.git
cd github-misp-feeder
pip install -r requirements.txt
python3 github-misp-feeder.py
