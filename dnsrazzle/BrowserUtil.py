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


__version__ = '1.5.3'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'



from .IOUtil import print_debug, print_error
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException

def screenshot_domain(driver, domain, out_dir):
    """
    function to take screenshot of supplied domain
    """
    url = "http://" + str(domain).strip('[]')
    try:
        driver.set_page_load_timeout(10)
        driver.get(url)
        ss_path = str(out_dir + domain + '.png')
        driver.get_screenshot_as_file(ss_path)
        return True
    except WebDriverException as exception:
        print_error(f"Unable to screenshot {domain}. {exception.msg}")
        # print_debug(exception.msg)
        return False


def get_webdriver(browser_name):
from fake_useragent import UserAgent
ua = UserAgent()
user_agent = ua.random
    try:
        if browser_name == 'chrome':
            options = webdriver.ChromeOptions()
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--headless")
            options.page_load_strategy = 'normal'
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                s = webdriver.chrome.service.Service(executable_path = ChromeDriverManager().install())
                return webdriver.Chrome(service=s, options=options)
            except Exception as E:
                print_error(f"Unable to install/update Chrome webdriver because of error: {E}")

        elif browser_name == 'firefox':
            user_agent = ua.random
            options = webdriver.FirefoxOptions()
            options.add_argument(f'--user-agent={user_agent}')
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--headless")
            options.page_load_strategy = 'normal'
            try:
                from webdriver_manager.firefox import GeckoDriverManager
                s = webdriver.firefox.service.Service(executable_path=GeckoDriverManager().install())
                return webdriver.Firefox(service=s, options=options)
            except Exception as E:
                print_error(f"Unable to install/update Firefox webdriver because of error:  {E}")

        else:
            print_error(f"Unimplemented webdriver browser: {browser_name}")
    except WebDriverException as exception:
        print_debug(exception.msg)


def quit_webdriver(driver):
    if driver is None:
        return
    try:
        driver.quit()
    except Exception as e:
        print_error(e)
