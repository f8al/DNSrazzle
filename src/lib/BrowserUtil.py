from src.lib.IOUtil import *
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
                return webdriver.Chrome(ChromeDriverManager().install(), options=options)
            except Exception as E:
                print_error(f"Unable to install/update Chrome webdriver because {E}")

        elif browser_name == 'firefox':
            options = webdriver.FirefoxOptions()
            # options.headless = True
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
    except e:
        print_error(e)