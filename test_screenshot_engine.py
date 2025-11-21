#!/usr/bin/env python3
"""
Quick test: Can we screenshot ANY accessible site?
This proves the screenshot engine works, regardless of vulns.
"""

import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def test_screenshot(url: str, output_file: str):
    """Test if we can screenshot a URL with our evasion techniques"""
    print(f"Testing screenshot capture of: {url}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox'
            ]
        )
        
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            extra_http_headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
            }
        )
        
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
            window.chrome = { runtime: {} };
        """)
        
        try:
            page = await context.new_page()
            print("Navigating to page...")
            await page.goto(url, wait_until='domcontentloaded', timeout=60000)
            
            print("Waiting for content to load...")
            await asyncio.sleep(3)
            
            print("Capturing screenshot...")
            await page.screenshot(path=output_file, full_page=True)
            
            print(f"✅ SUCCESS! Screenshot saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False
        finally:
            await browser.close()

if __name__ == '__main__':
    # Test with accessible sites
    test_urls = [
        'https://wordpress.org/news/',
        'https://httpbin.org/html',
        'https://example.com',
    ]
    
    for i, url in enumerate(test_urls):
        print(f"\n{'='*60}")
        print(f"Test {i+1}/{len(test_urls)}")
        print(f"{'='*60}")
        result = asyncio.run(test_screenshot(url, f'test_screenshot_{i+1}.png'))
        if result:
            print(f"Screenshot engine WORKS for: {url}")
            break

