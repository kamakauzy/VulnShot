#!/usr/bin/env python3
"""Quick test of the WPScan parser"""

import re

content = """_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://benefits.quikrete.com/ [198.51.136.28]
[+] Started: Wed Nov 12 14:39:15 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: server: Apache
"""

print("Testing URL extraction...")
print(f"Content length: {len(content)}")
print("\nSearching for URL pattern...")

# Test pattern 1
match1 = re.search(r'\[32m\[\+\]\[0m URL:\s+(https?://[^\s]+)', content)
print(f"Pattern 1 (ANSI): {match1}")

# Test pattern 2
match2 = re.search(r'^\[\+\]\s+URL:\s+(https?://[^\s]+)', content, re.MULTILINE)
print(f"Pattern 2 (plain, MULTILINE): {match2}")
if match2:
    print(f"  Matched: {match2.group(1)}")

# Let's try an even simpler pattern
match3 = re.search(r'\[\+\]\s+URL:\s+(https?://[^\s]+)', content)
print(f"Pattern 3 (plain, no MULTILINE): {match3}")
if match3:
    print(f"  Matched: {match3.group(1)}")

# Show the actual line
url_line = [line for line in content.split('\n') if 'URL:' in line]
print(f"\nActual URL line(s): {url_line}")

