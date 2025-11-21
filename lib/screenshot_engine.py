"""Screenshot engine with visual annotations for vulnerabilities"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List
from playwright.async_api import async_playwright, Page
from PIL import Image, ImageDraw, ImageFont
import io


class VulnScreenshotEngine:
    """Capture and annotate vulnerability screenshots"""
    
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.screenshots_dir = output_dir / 'screenshots'
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    async def capture_vulnerability_evidence(self, vuln_data: Dict) -> List[Dict]:
        """
        Capture visual evidence for all vulnerabilities
        
        Args:
            vuln_data: Parsed vulnerability data from scanner
            
        Returns:
            List of screenshot results with annotations
        """
        results = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox'
                ]
            )
            
            # Realistic browser context with WAF evasion
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                extra_http_headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"'
                }
            )
            
            # Anti-detection script
            await context.add_init_script("""
                // Remove webdriver flag
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => false
                });
                
                // Add realistic plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [
                        {name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer'},
                        {name: 'Chrome PDF Viewer', description: '', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
                        {name: 'Native Client', description: '', filename: 'internal-nacl-plugin'}
                    ]
                });
                
                // Realistic languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
                
                // Chrome runtime
                window.chrome = {
                    runtime: {}
                };
                
                // Permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({state: Notification.permission}) :
                        originalQuery(parameters)
                );
            """)
            
            # Capture WordPress version evidence
            if vuln_data.get('wordpress_version'):
                version_results = await self._capture_version_evidence(
                    context, vuln_data['url'], vuln_data['wordpress_version']
                )
                results.extend(version_results)
            
            # Capture theme evidence
            for theme in vuln_data.get('themes', []):
                theme_results = await self._capture_theme_evidence(
                    context, vuln_data['url'], theme
                )
                results.extend(theme_results)
            
            # Capture interesting findings
            for finding in vuln_data.get('interesting_findings', []):
                finding_results = await self._capture_finding_evidence(
                    context, finding
                )
                results.extend(finding_results)
            
            await browser.close()
        
        return results
    
    async def _capture_version_evidence(self, context, base_url: str, version_data: Dict) -> List[Dict]:
        """Capture WordPress version disclosure evidence"""
        results = []
        
        for disclosure_url_data in version_data.get('disclosure_urls', []):
            url = disclosure_url_data['url']
            
            try:
                page = await context.new_page()
                await page.goto(url, wait_until='networkidle', timeout=30000)
                
                # Take screenshot
                screenshot_bytes = await page.screenshot(full_page=True)
                
                # Get page content to find version string
                content = await page.content()
                
                await page.close()
                
                # Annotate the screenshot
                annotated_image = self._annotate_version_screenshot(
                    screenshot_bytes,
                    version_data['version'],
                    disclosure_url_data['element']
                )
                
                # Save
                filename = f"wp_version_{version_data['version'].replace('.', '_')}.png"
                filepath = self.screenshots_dir / filename
                annotated_image.save(filepath)
                
                results.append({
                    'type': 'wordpress_version',
                    'url': url,
                    'version': version_data['version'],
                    'found_by': version_data['found_by'],
                    'screenshot': str(filepath.relative_to(self.output_dir)),
                    'element': disclosure_url_data['element'],
                    'status': 'success'
                })
                
                self.logger.info(f"Captured WordPress version evidence: {url}")
                
            except Exception as e:
                self.logger.error(f"Failed to capture version evidence from {url}: {e}")
                results.append({
                    'type': 'wordpress_version',
                    'url': url,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return results
    
    async def _capture_theme_evidence(self, context, base_url: str, theme_data: Dict) -> List[Dict]:
        """Capture theme version evidence from style.css"""
        results = []
        
        style_url = theme_data.get('style_url')
        if not style_url:
            return results
        
        try:
            page = await context.new_page()
            
            # Navigate to style.css
            await page.goto(style_url, wait_until='networkidle', timeout=30000)
            
            # Take screenshot
            screenshot_bytes = await page.screenshot()
            
            await page.close()
            
            # Annotate
            annotated_image = self._annotate_theme_screenshot(
                screenshot_bytes,
                theme_data['name'],
                theme_data['version'],
                len(theme_data.get('vulnerabilities', []))
            )
            
            # Save
            safe_name = theme_data['name'].replace(' ', '_').replace('/', '_')
            filename = f"theme_{safe_name}_version.png"
            filepath = self.screenshots_dir / filename
            annotated_image.save(filepath)
            
            results.append({
                'type': 'theme_version',
                'url': style_url,
                'theme_name': theme_data['name'],
                'version': theme_data['version'],
                'vulnerabilities': theme_data.get('vulnerabilities', []),
                'screenshot': str(filepath.relative_to(self.output_dir)),
                'status': 'success'
            })
            
            self.logger.info(f"Captured theme evidence: {theme_data['name']}")
            
        except Exception as e:
            self.logger.error(f"Failed to capture theme evidence: {e}")
            results.append({
                'type': 'theme_version',
                'url': style_url,
                'status': 'failed',
                'error': str(e)
            })
        
        return results
    
    async def _capture_finding_evidence(self, context, finding: Dict) -> List[Dict]:
        """Capture evidence for interesting findings like XML-RPC"""
        results = []
        
        url = finding.get('url')
        if not url:
            return results
        
        try:
            page = await context.new_page()
            await page.goto(url, wait_until='networkidle', timeout=30000)
            
            screenshot_bytes = await page.screenshot()
            await page.close()
            
            # Annotate
            annotated_image = self._annotate_finding_screenshot(
                screenshot_bytes,
                finding['type'],
                finding.get('description', '')
            )
            
            # Save
            safe_type = finding['type'].replace(' ', '_').replace('/', '_')
            filename = f"finding_{safe_type}.png"
            filepath = self.screenshots_dir / filename
            annotated_image.save(filepath)
            
            results.append({
                'type': 'interesting_finding',
                'finding_type': finding['type'],
                'url': url,
                'description': finding.get('description'),
                'screenshot': str(filepath.relative_to(self.output_dir)),
                'status': 'success'
            })
            
            self.logger.info(f"Captured finding evidence: {finding['type']}")
            
        except Exception as e:
            self.logger.error(f"Failed to capture finding evidence: {e}")
            results.append({
                'type': 'interesting_finding',
                'url': url,
                'status': 'failed',
                'error': str(e)
            })
        
        return results
    
    def _annotate_version_screenshot(self, screenshot_bytes: bytes, version: str, element: str) -> Image:
        """Add annotations to WordPress version screenshot"""
        image = Image.open(io.BytesIO(screenshot_bytes))
        draw = ImageDraw.Draw(image)
        
        # Try to load a font, fall back to default
        try:
            font = ImageFont.truetype("arial.ttf", 24)
            font_large = ImageFont.truetype("arial.ttf", 32)
        except:
            font = ImageFont.load_default()
            font_large = ImageFont.load_default()
        
        # Add overlay at top
        overlay_height = 120
        draw.rectangle([(0, 0), (image.width, overlay_height)], fill=(220, 53, 69, 230))
        
        # Add text
        draw.text((20, 15), "🔴 VULNERABILITY FOUND", fill=(255, 255, 255), font=font_large)
        draw.text((20, 55), f"WordPress Version {version} Disclosed", fill=(255, 255, 255), font=font)
        draw.text((20, 85), f"Found in: {element}", fill=(255, 255, 255), font=font)
        
        return image
    
    def _annotate_theme_screenshot(self, screenshot_bytes: bytes, theme_name: str, version: str, vuln_count: int) -> Image:
        """Add annotations to theme screenshot"""
        image = Image.open(io.BytesIO(screenshot_bytes))
        draw = ImageDraw.Draw(image)
        
        try:
            font = ImageFont.truetype("arial.ttf", 24)
            font_large = ImageFont.truetype("arial.ttf", 32)
        except:
            font = ImageFont.load_default()
            font_large = ImageFont.load_default()
        
        # Color based on vuln count
        color = (220, 53, 69) if vuln_count > 0 else (255, 193, 7)
        
        overlay_height = 150
        draw.rectangle([(0, 0), (image.width, overlay_height)], fill=color + (230,))
        
        draw.text((20, 15), f"{'🔴' if vuln_count > 0 else '⚠️'} THEME VERSION FOUND", fill=(255, 255, 255), font=font_large)
        draw.text((20, 55), f"Theme: {theme_name}", fill=(255, 255, 255), font=font)
        draw.text((20, 85), f"Version: {version}", fill=(255, 255, 255), font=font)
        
        if vuln_count > 0:
            draw.text((20, 115), f"⚠️ {vuln_count} Known Vulnerabilities", fill=(255, 255, 255), font=font)
        
        return image
    
    def _annotate_finding_screenshot(self, screenshot_bytes: bytes, finding_type: str, description: str) -> Image:
        """Add annotations to interesting finding screenshot"""
        image = Image.open(io.BytesIO(screenshot_bytes))
        draw = ImageDraw.Draw(image)
        
        try:
            font = ImageFont.truetype("arial.ttf", 20)
            font_large = ImageFont.truetype("arial.ttf", 28)
        except:
            font = ImageFont.load_default()
            font_large = ImageFont.load_default()
        
        # Calculate overlay height based on description
        overlay_height = 100 if len(description) < 60 else 130
        draw.rectangle([(0, 0), (image.width, overlay_height)], fill=(255, 193, 7, 230))
        
        draw.text((20, 15), f"ℹ️ {finding_type}", fill=(0, 0, 0), font=font_large)
        
        # Word wrap description
        if description:
            words = description.split()
            lines = []
            current_line = []
            for word in words:
                current_line.append(word)
                if len(' '.join(current_line)) > 100:
                    lines.append(' '.join(current_line[:-1]))
                    current_line = [word]
            if current_line:
                lines.append(' '.join(current_line))
            
            y = 55
            for line in lines[:2]:  # Max 2 lines
                draw.text((20, y), line, fill=(0, 0, 0), font=font)
                y += 30
        
        return image

