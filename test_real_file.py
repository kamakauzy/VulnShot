#!/usr/bin/env python3
"""Test with the real file content"""

import re

# Exact content from line 15 of the real file
content = """[32m[+][0m URL: https://benefits.quikrete.com/ [198.51.136.28]"""

print("Testing URL extraction with ANSI codes...")
print(f"Content: {repr(content)}")

# Current pattern
match1 = re.search(r'\[32m\[\+\]\[0m URL:\s+(https?://[^\s]+)', content)
print(f"\nPattern 1 result: {match1}")
if match1:
    print(f"  Matched: {match1.group(1)}")
    url = match1.group(1).rstrip('/')
    url = re.sub(r'\s*\[[\d\.]+\]$', '', url)
    print(f"  After cleanup: {url}")

