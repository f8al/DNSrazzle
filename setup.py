
from setuptools import setup
from setuptools.command.install import install


class PostInstallMessage(install):
    """Print Playwright system dependency instructions after install."""
    def run(self):
        install.run(self)
        print("\n" + "=" * 70)
        print(" DNSrazzle — Post-Install Setup")
        print("=" * 70)
        print("\n Playwright requires a browser and system libraries to be installed.")
        print(" Run the following commands to complete setup:\n")
        print("   playwright install chromium")
        print("   sudo playwright install-deps chromium\n")
        print(" For Firefox support:\n")
        print("   playwright install firefox")
        print("   sudo playwright install-deps firefox\n")
        print("=" * 70 + "\n")


with open("docs/README.md", "r") as fh:
    long_description = fh.read()

setup(
	name='DNSrazzle',
	version='2.0.0',
    license='Apache',
	author='SecurityShrimp',
	author_email='securityshrimp@proton.me',
	description='DNS enumeration script',
	long_description=long_description,
    long_description_content_type='text/markdown',
	url='https://github.com/f8al/DNSrazzle',
    keywords=['DNS','screenshots','domain-fuzzing'],
	py_modules=['argparse',
                'playwright',
                'python-nmap',
                'opencv-python-headless',
                'os',
                'math',
                'dnstwist',
                'json',
                'scikit-image',
                'matplotlib',
                'tld',
                'dnspython',
                'progress',
                'dnsrecon'],
	entry_points={
		'console_scripts': ['DNSrazzle=DNSRazzle:main']
	},
    cmdclass={'install': PostInstallMessage},
    python_requires='>=3.7',
    data_files=[
        ('/etc/DNSrazzle',[
            './dictionaries/abused_tlds.dict',
            './dictionaries/common_tlds.dict',
            './dictionaries/english.dict',
            './dictionaries/polish.dict',
            './dictionaries/french.dict',
            './dictionaries/namelist.txt',
            './dictionaries/subdomains-top1mil.txt',
            './dictionaries/subdomains-top1mil-5000.txt',
            './dictionaries/subdomains-top1mil-20000.txt',
            './dictionaries/tlds-alpha-by-domain.txt'])
    ],
	classifiers = [
        'Development Status :: 1 - Beta',
        'Environment :: Console',
        'Intended Audience :: Security Researchers',
        'Intended Audience :: Security Engineers',
        'Intended Audience :: Threat Intelligence Analysts',
        'Intended Audience :: Incident Response Analysts',
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
    ],
)
