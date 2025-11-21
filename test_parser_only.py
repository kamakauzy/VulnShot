#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from lib.parsers.wpscan_parser import WPScanParser

parser = WPScanParser()
result = parser.parse('test_benefits.txt')

print(f"URL: {result.get('url')}")
print(f"WP Version: {result.get('wordpress_version')}")
print(f"Core Vulns: {len(result.get('wordpress_vulns', []))}")
print(f"Themes: {len(result.get('themes', []))}")
print(f"Findings: {len(result.get('interesting_findings', []))}")

if result.get('url'):
    print("\n✅ SUCCESS! Parser works!")
else:
    print("\n❌ FAILED! No URL extracted")

