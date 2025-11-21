#!/usr/bin/env python3
"""
VulnShot - Visual Vulnerability Evidence Generator
Automatically screenshot and annotate discovered vulnerabilities
"""

import argparse
import sys
import logging
import asyncio
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows
init()

from lib.parsers.wpscan_parser import WPScanParser
from lib.screenshot_engine import VulnScreenshotEngine
from lib.report_builder import VulnReportBuilder


class VulnShot:
    """Main VulnShot application"""
    
    def __init__(self, config=None):
        self.config = config or self._default_config()
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
    
    def _default_config(self) -> dict:
        """Default configuration"""
        return {
            'screenshots': {
                'timeout': 30,
                'full_page': True,
                'viewport': {
                    'width': 1920,
                    'height': 1080
                }
            },
            'logging': {
                'level': 'INFO'
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config['logging']['level'])
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=logging.DEBUG,  # Always show debug for troubleshooting
            format=log_format,
            handlers=[logging.StreamHandler()]
        )
    
    def run(self, args: argparse.Namespace):
        """Main execution flow"""
        start_time = datetime.now()
        
        print(f"\n{Fore.RED}{'='*60}")
        print(f"  🔴 VulnShot - Visual Vulnerability Evidence Generator")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # Parse scanner output
        if args.wpscan:
            self.logger.info(f"Parsing WPScan output: {args.wpscan}")
            parser = WPScanParser()
            
            try:
                scan_data = parser.parse(args.wpscan)
            except FileNotFoundError:
                print(f"{Fore.RED}Error: File not found: {args.wpscan}{Style.RESET_ALL}")
                sys.exit(1)
            except Exception as e:
                print(f"{Fore.RED}Error parsing file: {e}{Style.RESET_ALL}")
                self.logger.error(f"Parse error: {e}", exc_info=True)
                sys.exit(1)
            
            if not scan_data.get('url'):
                print(f"{Fore.RED}Error: Could not parse WPScan output{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Make sure the file is valid WPScan output in text format.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Run WPScan with: wpscan --url <target> --format cli-no-colour{Style.RESET_ALL}")
                sys.exit(1)
            
            print(f"{Fore.GREEN}✓ Parsed WPScan results{Style.RESET_ALL}")
            print(f"  Target: {Fore.CYAN}{scan_data['url']}{Style.RESET_ALL}")
            
            if scan_data.get('wordpress_version'):
                print(f"  WordPress: {Fore.YELLOW}{scan_data['wordpress_version']['version']}{Style.RESET_ALL}")
                print(f"  Core Vulnerabilities: {Fore.RED}{len(scan_data.get('wordpress_vulns', []))}{Style.RESET_ALL}")
            
            if scan_data.get('themes'):
                total_theme_vulns = sum(len(t.get('vulnerabilities', [])) for t in scan_data['themes'])
                print(f"  Themes: {len(scan_data['themes'])} ({Fore.RED}{total_theme_vulns} vulnerabilities{Style.RESET_ALL})")
            
            print()
        
        else:
            print(f"{Fore.RED}Error: No scanner output provided{Style.RESET_ALL}")
            sys.exit(1)
        
        # Setup output directory
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Capture visual evidence
        print(f"{Fore.CYAN}Capturing visual evidence...{Style.RESET_ALL}\n")
        
        screenshot_engine = VulnScreenshotEngine(self.config, output_dir)
        screenshots = asyncio.run(
            screenshot_engine.capture_vulnerability_evidence(scan_data)
        )
        
        successful = len([s for s in screenshots if s.get('status') == 'success'])
        failed = len([s for s in screenshots if s.get('status') == 'failed'])
        
        print(f"\n{Fore.GREEN}✓ Captured {successful} screenshots{Style.RESET_ALL}")
        if failed > 0:
            print(f"{Fore.YELLOW}⚠ {failed} failed{Style.RESET_ALL}")
        
        # Generate report
        print(f"\n{Fore.CYAN}Generating visual evidence report...{Style.RESET_ALL}\n")
        
        report_builder = VulnReportBuilder(output_dir)
        report_path = report_builder.generate(scan_data, screenshots)
        
        # Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  Summary")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Target: {scan_data['url']}")
        print(f"  Total Vulnerabilities: {Fore.RED}{len(scan_data.get('wordpress_vulns', []))}{Style.RESET_ALL}")
        print(f"  Visual Evidence: {Fore.GREEN}{successful} screenshots{Style.RESET_ALL}")
        print(f"  Duration: {duration:.2f}s")
        print(f"\n  Report: {Fore.YELLOW}{report_path}{Style.RESET_ALL}")
        print(f"  Screenshots: {Fore.YELLOW}{output_dir / 'screenshots'}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='VulnShot - Visual Vulnerability Evidence Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnshot.py --wpscan scan.txt --output ./evidence
  vulnshot.py --wpscan wpscan_results.txt --output ./vuln_report
        """
    )
    
    # Scanner inputs
    parser.add_argument('--wpscan', help='WPScan output file (text format)')
    # TODO: Add more scanner types
    # parser.add_argument('--nuclei', help='Nuclei JSON output')
    # parser.add_argument('--nikto', help='Nikto output file')
    
    # Output
    parser.add_argument('--output', '-o', default='vulnshot_output',
                       help='Output directory (default: vulnshot_output)')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.wpscan:
        parser.error("At least one scanner input is required (--wpscan)")
    
    # Run VulnShot
    try:
        vulnshot = VulnShot()
        vulnshot.run(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
