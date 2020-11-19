
from setuptools import setup

with open("docs/README.md", "r") as fh:
    long_description = fh.read()

setup(
	name='DNSrazzle',
	version=DNSrazzle.__version__,
    license='Apache',
	author='SecurityShrimp',
	author_email='@securityshrimp',
	description='DNS enumeration script',
	long_description=long_description,
    long_description_content_type='text/markdown',
	url='https://github.com/f8al/DNSrazzle',
    keywords=['DNS','screenshots','domain-fuzzing'],
	py_modules=['argparse',
                'selenium',
                'python-nmap',
                'opencv-python-headless',
                'imutils',
                'os',
                'math',
                'dnstwist',
                'json',
                'scikit-image',
                'webdriver-manager',
                'matplotlib',
                'tld',
                'whois',
                'dnspython',
                'progress'],
	entry_points={
		'console_scripts': ['DNSrazzle=DNSRazzle:main']
	},
    python_requires='>=3.7',
    data_files=[
        ('/etc/DNSrazzle',[
            'dictionaries/abused_tlds.dict',
            'dictionaries/common_tlds.dict',
            'dictionaries/english.dict',
            'dictionaries/polish.dict',
            'dictionaries/french.dict',
            'dictionaries/namelist.dict',
            'dictionaries/subdomains-top1mil.txt',
            'dictionaries/subdomains-top1mil-5000.txt',
            'dictionaries/subdomains-top1mil-20000.txt',
            'dictionaries/tlds-alpha-by-domain.txt'])
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