"""WPScan output parser"""

import re
import logging
from typing import List, Dict
from pathlib import Path


class WPScanParser:
    """Parse WPScan text output and extract vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, file_path: str) -> Dict:
        """
        Parse WPScan output file
        
        Returns:
            Dict with structure:
            {
                'url': str,
                'wordpress_version': str,
                'wordpress_vulns': [],
                'themes': [],
                'plugins': [],
                'interesting_findings': []
            }
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        result = {
            'url': self._extract_url(content),
            'wordpress_version': self._extract_wp_version(content),
            'wordpress_vulns': self._extract_wp_vulns(content),
            'themes': self._extract_themes(content),
            'plugins': self._extract_plugins(content),
            'interesting_findings': self._extract_interesting_findings(content)
        }
        
        return result
    
    def _extract_url(self, content: str) -> str:
        """Extract target URL"""
        # Try with ANSI color codes (colored output)
        match = re.search(r'\[32m\[\+\]\[0m URL:\s+(https?://[^\s]+)', content)
        if match:
            url = match.group(1)
            # Remove trailing slash and any IP notation in brackets
            url = url.rstrip('/')
            url = re.sub(r'\s*\[[\d\.]+\]$', '', url)
            self.logger.debug(f"Extracted URL (ANSI): {url}")
            return url
        
        # Try without ANSI codes (plain text output - more common)
        match = re.search(r'^\[\+\]\s+URL:\s+(https?://[^\s]+)', content, re.MULTILINE)
        if match:
            url = match.group(1)
            # Remove trailing slash and any IP notation in brackets
            url = url.rstrip('/')
            url = re.sub(r'\s*\[[\d\.]+\]$', '', url)
            self.logger.debug(f"Extracted URL (plain): {url}")
            return url
        
        self.logger.error("Could not extract URL from WPScan output")
        self.logger.debug(f"First 500 chars of content:\n{content[:500]}")
        return None
    
    def _extract_wp_version(self, content: str) -> Dict:
        """Extract WordPress version and vulnerabilities"""
        version_match = re.search(r'WordPress version ([0-9.]+) identified', content)
        if not version_match:
            return None
        
        version = version_match.group(1)
        
        # Extract the version disclosure method
        method_match = re.search(r'Found By: (.+?)\n', content[version_match.end():])
        found_by = method_match.group(1) if method_match else 'Unknown'
        
        # Extract URLs where version was found
        urls = []
        rss_match = re.search(r'- (https?://[^,\s]+/feed/)', content)
        if rss_match:
            urls.append({
                'url': rss_match.group(1),
                'type': 'RSS Feed',
                'element': 'generator tag'
            })
        
        return {
            'version': version,
            'found_by': found_by,
            'disclosure_urls': urls
        }
    
    def _extract_wp_vulns(self, content: str) -> List[Dict]:
        """Extract WordPress core vulnerabilities"""
        vulns = []
        
        # Find the WordPress version section
        version_section = re.search(
            r'WordPress version.*?(?=\n\[\+\]|\n\n\[\+\]|$)', 
            content, 
            re.DOTALL
        )
        if not version_section:
            return vulns
        
        section = version_section.group(0)
        
        # Extract individual vulnerabilities (works with both ANSI and plain text)
        # Pattern handles both [31m[!][0m (colored) and [!] (plain)
        vuln_pattern = (
            r'(?:\[31m)?\[!\](?:\[0m)?\s+Title:\s*(.+?)\n'
            r'(?:.*?CVSS:\s*([0-9.]+).*?\n)?'
            r'(?:.*?Fixed in:\s*([0-9.]+).*?\n)?'
            r'(?:.*?(https://cve\.mitre\.org/[^\s]+))?'
        )
        
        vuln_blocks = re.findall(vuln_pattern, section, re.DOTALL)
        
        for vuln in vuln_blocks:
            vulns.append({
                'title': vuln[0].strip(),
                'cvss': vuln[1].strip() if vuln[1] else None,
                'fixed_in': vuln[2].strip() if vuln[2] else None,
                'cve_url': vuln[3].strip() if vuln[3] else None,
                'component': 'WordPress Core'
            })
        
        return vulns
    
    def _extract_themes(self, content: str) -> List[Dict]:
        """Extract theme information and vulnerabilities"""
        themes = []
        
        # Find theme sections (both ANSI and plain text)
        theme_pattern = (
            r'(?:\[32m)?\[\+\](?:\[0m)?\s+WordPress theme in use:\s*(.+?)\n'
            r'(.*?)'
            r'(?=(?:\[32m)?\[\+\]|$)'
        )
        theme_sections = re.finditer(theme_pattern, content, re.DOTALL)
        
        for theme_section in theme_sections:
            theme_name = theme_section.group(1).strip()
            theme_content = theme_section.group(2)
            
            # Extract version
            version_match = re.search(r'Version:\s*([0-9.]+)', theme_content)
            version = version_match.group(1) if version_match else None
            
            # Extract location
            location_match = re.search(r'Location:\s*(https?://[^\s]+)', theme_content)
            location = location_match.group(1) if location_match else None
            
            # Extract style URL
            style_match = re.search(r'Style URL:\s*(https?://[^\s]+)', theme_content)
            style_url = style_match.group(1) if style_match else None
            
            # Extract vulnerabilities (both ANSI and plain)
            vuln_pattern = (
                r'(?:\[31m)?\[!\](?:\[0m)?\s+Title:\s*(.+?)\n'
                r'(?:.*?CVSS:\s*([0-9.]+).*?\n)?'
                r'(?:.*?Fixed in:\s*([0-9.]+).*?\n)?'
            )
            vuln_blocks = re.findall(vuln_pattern, theme_content, re.DOTALL)
            
            vulns = []
            for vuln in vuln_blocks:
                vulns.append({
                    'title': vuln[0].strip(),
                    'cvss': vuln[1].strip() if vuln[1] else None,
                    'fixed_in': vuln[2].strip() if vuln[2] else None
                })
            
            themes.append({
                'name': theme_name,
                'version': version,
                'location': location,
                'style_url': style_url,
                'vulnerabilities': vulns
            })
        
        return themes
    
    def _extract_plugins(self, content: str) -> List[Dict]:
        """Extract plugin information (for future)"""
        # TODO: Implement when we have plugin examples
        return []
    
    def _extract_interesting_findings(self, content: str) -> List[Dict]:
        """Extract interesting findings like XML-RPC, directory listing, etc."""
        findings = []
        
        # XML-RPC (both ANSI and plain text)
        xmlrpc_match = re.search(
            r'(?:\[32m)?\[\+\](?:\[0m)?\s+XML-RPC seems to be enabled:\s*(https?://[^\s]+)', 
            content
        )
        if xmlrpc_match:
            findings.append({
                'type': 'XML-RPC Enabled',
                'url': xmlrpc_match.group(1),
                'severity': 'info',
                'description': 'XML-RPC interface is exposed and could be used for brute force attacks'
            })
        
        return findings

