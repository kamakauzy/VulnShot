# VulnShot

![VulnShot Banner](config/VulnShot.png)

**Because "It's vulnerable" without a screenshot is just your opinion, Karen.**

## What Fresh Hell Is This?

Look, we all know the drill: You run wpscan, it spits out 47 vulnerabilities in Comic Sans, you copy-paste them into a report, and the client responds with *"Can you prove it?"*

Enter VulnShot. It takes your scanner output, navigates to the actual vulnerable shit, and screenshots the evidence with big red annotations that even a C-suite executive can understand. WordPress 4.8.25 leaking in the RSS feed? SCREENSHOT. Outdated Divi theme with 8 CVEs? SCREENSHOT. XML-RPC enabled because why not? SCREENSHOT.

It's like having a paralegal for your pen test, but it doesn't bill by the hour.

## Why Does This Exist?

- **Visual Evidence**: Because "trust me bro" doesn't fly in pen test reports
- **Client Comprehension**: Red boxes and arrows > JSON blobs
- **Time Savings**: Screenshot 50 vulns in 5 minutes instead of 5 hours
- **Report Flex**: Your reports now look professional AF

## What It Does (POC Edition)

### Currently Supported Scanners
- WPScan - WordPress vulns, themes, plugins, the whole shebang

### Coming Soon
- Nuclei (because we love templates)
- Nikto (nostalgia edition)
- Burp Suite (when we feel fancy)
- Your favorite scanner (open an issue)

## Features (That Actually Work)

### Smart Screenshot Engine
- Auto-navigates to RSS feeds, style.css, xmlrpc.php
- Finds version strings like a bloodhound
- Takes full-page screenshots (no cropped garbage)
- Works headless (no browser windows popping up)

### Aggressive Annotations
- Big red overlays you can't miss
- Version numbers highlighted
- CVE counts front and center
- "VULNERABILITY FOUND" in case anyone's confused

### Slick Reports
- Dark mode (obviously - we're not monsters)
- Stats dashboard (high/medium/low risk)
- Click to zoom on screenshots
- Organized by vulnerability type
- Looks way better than your current reports

### Actually Intelligent
- Parses WPScan output (even the ugly parts)
- Extracts CVSS scores automatically
- Matches vulns to visual evidence
- Handles failures gracefully (unlike that one coworker)

## Installation (It's Not That Hard)

### Windows Quick Test
```cmd
quicktest.bat
```
Seriously, just run this. It does everything.

### Manual Install (For The Control Freaks)
```bash
# Clone this bad boy
git clone https://github.com/kamakauzy/VulnShot.git
cd VulnShot

# Install deps
pip install -r requirements.txt

# Install Playwright browser (yes, it's needed)
playwright install chromium
```

## Usage

### Option 1: Try The Example (Recommended)
```bash
python vulnshot.py --wpscan examples/example_wpscan.txt --output test_output
```

This uses real WPScan output from a real site (sanitized, relax).

### Option 2: Your Own Scans
```bash
# Run WPScan (text output, not JSON)
wpscan --url https://target.com --api-token YOUR_TOKEN > scan.txt

# Feed it to VulnShot
python vulnshot.py --wpscan scan.txt --output evidence/

# Open the report
# evidence/vulnshot_report.html
```

## What You Get

### Visual Evidence Screenshots
- WordPress version in RSS generator tags (big red overlay)
- Theme version from style.css (with vuln count)
- XML-RPC endpoint if enabled
- Each annotated with severity and details

### HTML Report Includes:
- Stats dashboard (total vulns, risk levels)
- WordPress core vulnerabilities with CVE links
- Theme vulnerabilities with CVSS scores
- Interesting findings (exposed files, etc.)
- Every vulnerability gets a screenshot
- Click to zoom on any image
- Professional enough for client delivery

## Example Output

**Before VulnShot:**
```
[+] WordPress version 4.8.25 identified
[!] 2 vulnerabilities identified
```
*Client: "Is this bad?"*

**After VulnShot:**
*Opens report with massive red screenshot showing "VULNERABILITY FOUND - WordPress Version 4.8.25 Disclosed - Found in: RSS Feed generator tag"*

*Client: "Oh shit, fix this."*

## Project Status

**POC Complete** - Core functionality working

**Working:**
- WPScan parser
- Screenshot engine with annotations
- Visual evidence report generation
- Version disclosure detection
- Theme vulnerability detection

**TODO:**
- Add more scanner support (Nuclei, Nikto)
- Plugin vulnerability screenshots
- XSS injection point screenshots
- SQL error message capture
- Directory listing evidence

## Contributing

Got ideas? Found bugs? Want to add support for your favorite scanner?

Open an issue or PR. We're friendly (mostly).

## License

Internal tool. Don't be weird about it.

---

**VulnShot**: *Because vulnerability reports without screenshots are just elaborate blog posts.*


