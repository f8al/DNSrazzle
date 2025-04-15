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

Copyright 2023 SecurityShrimp

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


__version__ = '1.5.4'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

from .IOUtil import print_debug, print_error

def get_webdriver(browser_name):
    from fake_useragent import UserAgent
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    import selenium

    ua = UserAgent()
    user_agent = ua.random

    # Ensure Selenium version compatibility
    required_version = (4, 6, 0)
    current_version = tuple(map(int, selenium.__version__.split(".")[:3]))
    if current_version < required_version:
        raise RuntimeError(f"Selenium 4.6.0+ required, found {selenium.__version__}")

    try:
        if browser_name == 'chrome':
            options = ChromeOptions()
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--headless=new")
            options.page_load_strategy = 'normal'
            return webdriver.Chrome(service=ChromeService(), options=options)

        elif browser_name == 'firefox':
            options = FirefoxOptions()
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--width=1920")
            options.add_argument("--height=1080")
            options.add_argument("--headless")
            return webdriver.Firefox(service=FirefoxService(), options=options)

        else:
            print_error(f"Unsupported browser type: {browser_name}")
            return None

    except Exception as E:
        print_error(f"Failed to start {browser_name} driver: {E}")
        return None
