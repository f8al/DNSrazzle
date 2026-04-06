#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2025 SecurityShrimp LTD, LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


__version__ = '2.0.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

import os
import random

from playwright.async_api import async_playwright, Browser, TimeoutError as PlaywrightTimeout
from .IOUtil import print_debug, print_error

# User-agent rotation list
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Module-level Playwright instance (reused across calls within one asyncio.run)
_playwright_instance = None


async def _get_playwright():
    """Get or create the module-level Playwright instance."""
    global _playwright_instance
    if _playwright_instance is None:
        _playwright_instance = await async_playwright().start()
    return _playwright_instance


async def create_browser(browser_name: str = "chromium") -> Browser | None:
    """Launch a Playwright browser instance.

    Args:
        browser_name: "chromium" or "firefox"

    Returns:
        Browser instance, or None on failure.
    """
    try:
        pw = await _get_playwright()

        if browser_name == "chromium":
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                ],
            )
        elif browser_name == "firefox":
            browser = await pw.firefox.launch(headless=True)
        else:
            print_error(f"Unsupported browser type: {browser_name}")
            return None

        print_debug(f"Playwright {browser_name} browser started successfully")
        return browser

    except Exception as e:
        print_error(f"Failed to start Playwright {browser_name} browser: {e}")
        return None


async def screenshot_domain(browser: Browser, domain: str, out_dir: str, retries: int = 1) -> bool:
    """Take a screenshot of a domain using a fresh browser context.

    Each screenshot gets its own context (isolated cookies, cache, storage).
    The context is closed after the screenshot regardless of success/failure.

    Args:
        browser: Playwright Browser instance (shared across screenshots).
        domain: Domain name to screenshot.
        out_dir: Directory to save the screenshot PNG.
        retries: Number of retry attempts on timeout/navigation errors.

    Returns:
        True if screenshot was saved, False otherwise.
    """
    if not browser:
        print_error("Browser not initialized — skipping screenshot.")
        return False

    url = "http://" + str(domain).strip("[]")
    ss_path = os.path.join(out_dir, f"{domain}.png")
    os.makedirs(out_dir, exist_ok=True)

    user_agent = random.choice(_USER_AGENTS)

    for attempt in range(retries + 1):
        context = None
        try:
            context = await browser.new_context(
                user_agent=user_agent,
                viewport={"width": 1920, "height": 1080},
            )
            page = await context.new_page()
            page.set_default_navigation_timeout(10_000)  # 10 seconds

            await page.goto(url, wait_until="load")
            await page.screenshot(path=ss_path, full_page=False)
            return True

        except PlaywrightTimeout:
            print_error(
                f"Timeout loading {url} (attempt {attempt + 1} of {retries + 1})"
            )
            if attempt < retries:
                continue
            else:
                print_debug(f"Skipping {domain} after {retries + 1} failed attempts")
                return False

        except Exception as e:
            message = str(e).lower()
            retryable = any(kw in message for kw in [
                "timeout", "net::err_", "renderer", "navigation failed",
            ])
            if retryable and attempt < retries:
                print_error(
                    f"Retryable error for {url}: {e} (attempt {attempt + 1} of {retries + 1})"
                )
                continue
            else:
                print_error(f"Unable to screenshot {domain}: {e}")
                return False

        finally:
            if context:
                try:
                    await context.close()
                except Exception:
                    pass

    return False


async def close_browser(browser: Browser | None) -> None:
    """Close a Playwright browser instance."""
    if browser is None:
        return
    try:
        await browser.close()
    except Exception as e:
        print_error(f"Error while closing browser: {e}")


async def cleanup_playwright() -> None:
    """Stop the module-level Playwright instance. Call at end of async session."""
    global _playwright_instance
    if _playwright_instance is not None:
        try:
            await _playwright_instance.stop()
        except Exception:
            pass
        _playwright_instance = None
