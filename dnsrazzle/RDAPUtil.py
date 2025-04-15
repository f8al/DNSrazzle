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

Copyright 2025 SecurityShrimp

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


import requests
import re
from urllib.parse import urljoin
from threading import Lock

class RDAPClient:
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    _bootstrap_lock = Lock()
    _rdap_endpoints = {}

    def __init__(self):
        if not RDAPClient._rdap_endpoints:
            self._load_rdap_endpoints()

    def _load_rdap_endpoints(self):
        """Fetch and cache RDAP base URLs for each TLD from IANA's bootstrap."""
        with self._bootstrap_lock:
            try:
                response = requests.get(self.BOOTSTRAP_URL, timeout=10)
                response.raise_for_status()
                data = response.json()
                for entry in data.get("services", []):
                    tlds = entry[0]
                    urls = entry[1]
                    for tld in tlds:
                        RDAPClient._rdap_endpoints[tld.lower()] = urls[0].rstrip("/") + "/"
            except requests.RequestException:
                # Avoid leaking internal exception details
                print("[!] Failed to fetch RDAP bootstrap data from IANA.")
            except ValueError:
                print("[!] Malformed JSON in RDAP bootstrap response.")

    def _get_rdap_url_for_domain(self, domain):
        """Returns a fully formed RDAP lookup URL for a domain, or None if not supported."""
        if not self._is_valid_domain(domain):
            return None
        tld = domain.lower().split(".")[-1]
        base_url = RDAPClient._rdap_endpoints.get(tld)
        if base_url:
            return urljoin(base_url, f"domain/{domain}")
        return None

    def _is_valid_domain(self, domain):
        """Basic validation to ensure domain is safe for lookup."""
        domain_regex = re.compile(
            r"^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
        )
        return bool(domain_regex.match(domain))

    def lookup(self, domain):
        """
        Perform an RDAP lookup for the given domain.
        Returns RDAP JSON or None on failure.
        """
        rdap_url = self._get_rdap_url_for_domain(domain)
        if not rdap_url:
            print(f"[!] Invalid or unsupported domain: {domain}")
            return None

        try:
            response = requests.get(rdap_url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            print(f"[!] RDAP lookup failed for {domain} (HTTP {status})")
        except requests.exceptions.Timeout:
            print(f"[!] RDAP lookup timed out for {domain}")
        except requests.RequestException:
            print(f"[!] Network error during RDAP lookup for {domain}")
        except ValueError:
            print(f"[!] Failed to decode RDAP response for {domain}")
        return None
