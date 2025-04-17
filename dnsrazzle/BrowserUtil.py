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


__version__ = '1.6.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

from .IOUtil import print_debug, print_error
from selenium.common.exceptions import WebDriverException
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
import selenium
import tempfile
import os
import shutil
import time

def get_webdriver(browser_name):
    ua = UserAgent()
    user_agent = ua.random

    # Ensure Selenium version
    required_version = (4, 6, 0)
    current_version = tuple(map(int, selenium.__version__.split(".")[:3]))
    if current_version < required_version:
        raise RuntimeError(f"Selenium 4.6.0+ required, found {selenium.__version__}")

    try:
        if browser_name == 'chrome':
            options = ChromeOptions()
            options.page_load_strategy = 'normal'
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-extensions")
            options.add_argument("--single-process")
            options.add_argument("--log-level=3")  # INFO = 0, WARNING = 1, LOG_ERROR = 2, LOG_FATAL = 3

            ## ✅ Hardened temp directory location to avoid /tmp noexec issues
            base_tmp = "/var/tmp/dnsrazzle-profiles"
            os.makedirs(base_tmp, exist_ok=True)
            temp_profile = tempfile.mkdtemp(dir=base_tmp, prefix="chrome-profile-")
            options.add_argument(f"--user-data-dir={temp_profile}")

            print_debug(f"Creating Chrome temp profile at: {temp_profile}")

            driver = webdriver.Chrome(
                service=ChromeService(), 
                options=options)
            driver.temp_profile_dir = temp_profile  # ✅ now that driver is defined
            print_debug(f"Chrome started successfully using: {temp_profile}")


            return driver

        elif browser_name == 'firefox':
            options = FirefoxOptions()
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--headless")
            options.add_argument("--width=1920")
            options.add_argument("--height=1080")

            # ✅ Isolated temporary profile directory
            base_tmp = "/var/tmp/dnsrazzle-profiles"
            os.makedirs(base_tmp, exist_ok=True)
            temp_profile = tempfile.mkdtemp(dir=base_tmp, prefix="firefox-profile-")

            profile = FirefoxProfile(temp_profile)
            profile.set_preference("layers.acceleration.disabled", True)

            # ✅ Assign FirefoxProfile to options correctly
            options.profile = profile

            print_debug(f"Creating Firefox temp profile at: {temp_profile}")

            driver = webdriver.Firefox(
                service=FirefoxService(),
                options=options
            )
            driver.temp_profile_dir = temp_profile
            print_debug(f"Firefox started successfully using: {temp_profile}")

            return driver


        else:
            print_error(f"Unsupported browser type: {browser_name}")
            return None

    except WebDriverException as E:
        print_error(f"Failed to start {browser_name} driver: {E}")
        # Cleanup on Chrome failure
        if 'temp_profile' in locals():
            shutil.rmtree(temp_profile, ignore_errors=True)
        return None

def screenshot_domain(driver, domain, out_dir, retries=1):
    """
    Function to take screenshot of supplied domain.
    It retries if a known error occurs (e.g. timeout or renderer issues).
    """
    if not driver:
        print_error("WebDriver not initialized — skipping screenshot.")
        return False

    url = "http://" + str(domain).strip('[]')
    ss_path = os.path.join(out_dir, f"{domain}.png")
    
    retryable_keywords = [
        "timeout", 
        "renderer", 
        "net::err_address_unreachable", 
        "net::err_"
    ]

    for attempt in range(retries + 1):
        try:
            driver.set_page_load_timeout(15)
            driver.get(url)
            driver.get_screenshot_as_file(ss_path)
            return True

        except WebDriverException as exception:
            # 🔧 Use .msg for cleaner error messages, fallback to str()
            message = getattr(exception, "msg", str(exception)).lower()

            if any(keyword in message for keyword in retryable_keywords):
                print_error(f"Chrome error while loading {url}: {message}. Retrying... (attempt {attempt + 1} of {retries + 1})")
                if attempt < retries:
                    time.sleep(1)
                    continue
                else:
                    print_debug(f"Skipping {domain} after {retries + 1} failed attempts: {message}")
                    return False
            else:
                print_error(f"Unable to screenshot {domain}. {message}")
                return False

    return False


def quit_webdriver(driver):
    if driver is None:
        return
    try:
        driver.quit()
        if hasattr(driver, "temp_profile_dir"):
            shutil.rmtree(driver.temp_profile_dir, ignore_errors=True)
    except Exception as e:
        print_error(f"Error while quitting WebDriver: {e}")
