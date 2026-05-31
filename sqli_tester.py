# sqli_tester.py
# error-based SQL injection detection
# we're looking for db errors leaking into responses, classic rookie mistake by devs
# IMPORTANT: only run this on apps you own or have written permission to test. fr.

import requests
from urllib.parse import urljoin
from src.utils import load_payloads

# these are strings that show up in SQL error messages
# different databases have different errors, gotta catch em all lol
SQL_ERRORS = [
    # MySQL - the most common one out here
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    # MSSQL
    "microsoft ole db provider",
    "odbc sql server driver",
    "syntax error converting",
    # Oracle - rare but exists
    "ora-01756",
    "oracle error",
    # PostgreSQL
    "pg_query",
    "postgresql",
    "psql error",
    # SQLite
    "sqlite_error",
    "sqlite3.operationalerror",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "query failed",
]


class SQLiTester:
    def __init__(self, payload_file="src/payloads/sqli.txt", timeout=5, verbose=False):
        self.payloads = load_payloads(payload_file)
        self.timeout = timeout
        self.verbose = verbose
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        if not self.payloads:
            print("[!] sqli payload file is empty or missing, that's gonna be a problem")

    def test_forms(self, forms):
        """
        loops through all discovered forms and fires sqli payloads at em
        returns a list of anything sus we find
        """
        print(f"\n[*] testing {len(forms)} form(s) for SQL injection...")

        for form in forms:
            self._test_form(form)

        if self.vulnerabilities:
            print(f"[!] found {len(self.vulnerabilities)} potential SQLi vulnerability(s)!")
        else:
            print("[+] no obvious SQLi errors detected in forms")

        return self.vulnerabilities

    def _test_form(self, form):
        """
        submits each payload into each input field of a form
        and checks if the response has any sql error strings in it
        """
        action = form['action']
        method = form['method']
        page_url = form['page_url']

        # build the full action url
        # sometimes action is relative, sometimes absolute, gotta handle both smh
        if action.startswith('http'):
            target_url = action
        elif action:
            target_url = urljoin(page_url, action)
        else:
            # empty action means it submits to itself
            target_url = page_url

        for payload in self.payloads:
            # build form data with payload injected into every field
            # yeah this is brute-force-y but it works
            data = {}
            for inp in form['inputs']:
                data[inp['name']] = payload  # inject everywhere

            try:
                if method == 'post':
                    response = self.session.post(target_url, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=data, timeout=self.timeout)

                # check response for known SQL error strings
                response_lower = response.text.lower()
                detected_error = self._check_for_errors(response_lower)

                if detected_error:
                    vuln = {
                        'type': 'SQL Injection',
                        'url': target_url,
                        'method': method.upper(),
                        'payload': payload,
                        'evidence': detected_error,
                        'severity': 'HIGH'  # sqli is always high, no cap
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!!!] SQLi hit on {target_url}")
                    print(f"        payload: {payload}")
                    print(f"        evidence: {detected_error}")
                    # found one, no need to keep hammering with more payloads
                    break

                if self.verbose:
                    print(f"  [-] no error with payload: {payload[:30]}...")

            except requests.exceptions.Timeout:
                if self.verbose:
                    print(f"  [!] request timed out for {target_url}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    print(f"  [!] connection dropped for {target_url}")
            except Exception as e:
                if self.verbose:
                    print(f"  [!] something broke: {e}")

    def _check_for_errors(self, response_text):
        """
        scans the response body for known sql error strings
        returns the matched error string or None if nothing found
        """
        for error in SQL_ERRORS:
            if error in response_text:
                return error
        return None
