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


__version__ = '1.5.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'



from .IOUtil import print_debug, print_error, print_good, print_status
from selenium import webdriver
from selenium.common.exceptions import WebDriverException


def screenshot_domain(driver, domain, out_dir):
    """
    function to take screenshot of supplied domain
    """
    print_status(f"collecting screenshot of {domain}!")
    url = "http://" + str(domain).strip('[]')
    try:
        driver.get(url)
        ss_path = str(out_dir + domain + '.png')
        driver.set_window_size(1920, 1080)  # May need manual adjustment
        driver.get_screenshot_as_file(ss_path)
        print_good(f"Screenshot for {domain} saved to {ss_path}")
    except WebDriverException as exception:
        print_error(f"Unable to screenshot {domain}!")
        print_debug(exception.msg)


def get_webdriver(browser_name):
    try:
        if browser_name == 'chrome':
            options = webdriver.ChromeOptions()
            options.headless = True
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                s = webdriver.chrome.service.Service(executable_path = ChromeDriverManager().install())
                return webdriver.Chrome(service=s, options=options)
            except Exception as E:
                print_error(f"Unable to install/update Chrome webdriver because {E}")

        elif browser_name == 'firefox':
            options = webdriver.FirefoxOptions()
            options.headless = True
            try:
                from webdriver_manager.firefox import GeckoDriverManager
                s = webdriver.firefox.service.Service(executable_path=GeckoDriverManager().install())
                return webdriver.Firefox(service=s, options=options)
            except Exception as E:
                print_error(f"Unable to install/update Firefox webdriver because {E}")

        else:
            print_status(f"Unimplemented webdriver browser: {browser_name}")
    except WebDriverException as exception:
        print_debug(exception.msg)


def quit_webdriver(driver):
    try:
        driver.quit()
    except Exception as e:
        print_error(e)
