# xss_tester.py
# reflected XSS detection - we inject payloads and check if they bounce back unescaped
# this catches the lazy devs who forgot to sanitize their inputs lol
# DISCLAIMER: authorized testing only. you know the deal.

import requests
from urllib.parse import urljoin
from src.utils import load_payloads


class XSSTester:
    def __init__(self, payload_file="src/payloads/xss.txt", timeout=5, verbose=False):
        self.payloads = load_payloads(payload_file)
        self.timeout = timeout
        self.verbose = verbose
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        if not self.payloads:
            print("[!] xss payload file empty or missing, we flying blind rn")

    def test_forms(self, forms):
        """
        fires xss payloads into all discovered forms
        reflected XSS = payload shows up raw in the response HTML
        stored XSS is a whole different beast, not covering that here
        """
        print(f"\n[*] testing {len(forms)} form(s) for reflected XSS...")

        for form in forms:
            self._test_form(form)

        if self.vulnerabilities:
            print(f"[!] found {len(self.vulnerabilities)} potential XSS vulnerability(s)!")
        else:
            print("[+] no reflected XSS detected in forms")

        return self.vulnerabilities

    def _test_form(self, form):
        """
        submits xss payloads and checks if they reflect back unescaped
        if <script>alert(1)</script> shows up raw in response... yeah that's bad lol
        """
        action = form['action']
        method = form['method']
        page_url = form['page_url']

        if action.startswith('http'):
            target_url = action
        elif action:
            target_url = urljoin(page_url, action)
        else:
            target_url = page_url

        for payload in self.payloads:
            data = {}
            for inp in form['inputs']:
                # inject into every field, we don't discriminate
                data[inp['name']] = payload

            try:
                if method == 'post':
                    response = self.session.post(target_url, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=data, timeout=self.timeout)

                # check if our exact payload is sitting raw in the response
                # proper apps would escape < > " etc. bad apps just... don't lol
                if payload in response.text:
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': target_url,
                        'method': method.upper(),
                        'payload': payload,
                        'evidence': f"payload reflected unescaped in response",
                        'severity': 'HIGH'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!!!] XSS reflected on {target_url}")
                    print(f"        payload: {payload[:60]}")
                    # found one, move to next form
                    break

                if self.verbose:
                    print(f"  [-] payload not reflected: {payload[:40]}...")

            except requests.exceptions.Timeout:
                if self.verbose:
                    print(f"  [!] timed out on {target_url}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    print(f"  [!] connection died on {target_url}")
            except Exception as e:
                if self.verbose:
                    print(f"  [!] ruh roh: {e}")
