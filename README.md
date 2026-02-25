# 🎯 TakeoverHunter v1.0

**Find confirmed subdomain takeovers, not just potentials.**

An autonomous bug bounty tool that finds **exploitable** subdomain takeovers and generates HackerOne-ready reports.

---

## 🚀 What Makes This Different?

| Other Tools | TakeoverHunter |
|-------------|----------------|
| Find dangling CNAMEs | **Actually verify if takeover is possible** |
| Dump raw lists | **Generate ready-to-submit reports** |
| High false positives | **Zero false positives (confirmed only)** |
| Generic scanners | **Focused on one bug class, done right** |

---

## 🛠️ Installation

### Requirements
- Python 3.7+
- Parrot OS / Kali Linux / Ubuntu
- Go (for security tools)

### Quick Install

```bash
# Clone repository
git clone https://github.com/hemanthshashidhar/subdomain-takeover.git
cd TakeoverHunter

# Make installer executable
chmod +x install_tools.sh

# Run installer (takes 5-10 minutes)
./install_tools.sh

# Restart terminal or source
source ~/.bashrc


Manual Install

# Python dependencies
pip3 install requests dnspython urllib3

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
sudo apt install amass


🎯 Usage

# Make executable
chmod +x takeoverhunter.py

# Run against target
./takeoverhunter.py example.com

# Or with Python
python3 takeoverhunter.py example.com


Test on Safe Target

# Should find no takeovers (properly configured)
./takeoverhunter.py scanme.nmap.org


Real Bug Bounty Target

# Only test on programs you're authorized for!
./takeoverhunter.py hackerone.com


🔍 How It Works

PHASE 1: FIND SUBDOMAINS
   ↓ subfinder + assetfinder + amass
   ↓ Deduplicate and sort

PHASE 2: CHECK DNS RECORDS
   ↓ Query CNAME for each subdomain
   ↓ Detect cloud services (AWS, GitHub, Azure, etc.)

PHASE 3: VALIDATE TAKEOVERS
   ↓ Actually try to claim the resource (safe check)
   ↓ Confirm if vulnerable or not
   ↓ Zero false positives!

PHASE 4: GENERATE REPORTS
   ↓ HackerOne markdown format
   ↓ Step-by-step reproduction
   ↓ Ready to copy-paste and submit



  📊 Example Output

  🎯 TakeoverHunter initialized for: example.com
📁 Output: takeover_example.com_20250122_143052/

============================================================
🔍 PHASE 1: Finding Subdomains
============================================================

[1/3] Running subfinder...
    ✅ Found 45 subdomains

[2/3] Running assetfinder...
    ✅ Found 23 subdomains

[3/3] Running amass...
    ✅ Found 67 subdomains

📊 Total unique subdomains: 89

============================================================
🔍 PHASE 2: Checking DNS Records (CNAME)
============================================================

[5/89] Checking api.example.com...
    CNAME: api-example.github.io
    ☁️  Detected: GitHub Pages
    → Added to candidates

📊 Found 3 potential takeover candidates

============================================================
🔍 PHASE 3: Validating Takeovers (Safe Checks)
============================================================

🧪 Testing: api.example.com
   Service: GitHub Pages
   CNAME: api-example.github.io
   🚨 CONFIRMED VULNERABLE!
   Impact: HIGH - Can claim GitHub username and serve malicious content

🎯 Confirmed takeovers: 1

============================================================
📝 PHASE 4: Generating Reports
============================================================

✅ Report generated: report_api.example.com.md
   Subdomain: api.example.com
   Service: GitHub Pages
   Impact: HIGH - Can claim GitHub username and serve malicious content

============================================================
✅ SCAN COMPLETE
============================================================

📁 Results in: takeover_example.com_20250122_143052/
🎯 Confirmed takeovers: 1

🚀 Ready to submit:
   • api.example.com (GitHub Pages)
     Report: report_api.example.com.md


Generated Report Structure

takeover_example.com_20250122_143052/
├── all_subdomains.txt          # Raw subdomain list
├── SUMMARY.json                # JSON summary of findings
├── evidence/
│   └── api.example.com.json    # Technical evidence
└── report_api.example.com.md   # HackerOne-ready report


⚠️ Legal & Ethical Use

ONLY test on:

    ✅ Bug bounty programs you're registered for
    ✅ Programs with explicit wildcard scope
    ✅ Your own infrastructure
    ✅ Intentionally vulnerable test environments

NEVER test on:

    ❌ Government websites
    ❌ Banks or financial institutions (without invitation)
    ❌ Healthcare systems
    ❌ Any site without permission

 🤝 Contributing

 This is an open-source tool for the security community.
Ways to contribute:

    Report bugs
    Add new takeover services
    Improve validation methods
    Share findings and techniques
    Help others learn bug bounty


    Tools used:

    subfinder - ProjectDiscovery
    assetfinder - TomNomNom
    amass - OWASP
