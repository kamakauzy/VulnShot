#!/usr/bin/env python3
"""Quick test script for VulnShot POC"""

import sys
import subprocess
from pathlib import Path

def main():
    print("=" * 60)
    print("  VulnShot POC - Quick Test")
    print("=" * 60)
    print()
    
    # Check if example file exists
    example_file = Path("examples/example_wpscan.txt")
    if not example_file.exists():
        print("❌ Example file not found!")
        print(f"   Looking for: {example_file.absolute()}")
        sys.exit(1)
    
    print(f"✓ Found example WPScan output: {example_file}")
    print()
    
    # Run VulnShot
    print("Running VulnShot...")
    print("-" * 60)
    
    cmd = [
        sys.executable,
        "vulnshot.py",
        "--wpscan", str(example_file),
        "--output", "test_output"
    ]
    
    result = subprocess.run(cmd, capture_output=False)
    
    if result.returncode == 0:
        print()
        print("=" * 60)
        print("✓ Test completed successfully!")
        print("=" * 60)
        print()
        print("Check the output:")
        print("  Report:      test_output/vulnshot_report.html")
        print("  Screenshots: test_output/screenshots/")
        print()
    else:
        print()
        print("❌ Test failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()

