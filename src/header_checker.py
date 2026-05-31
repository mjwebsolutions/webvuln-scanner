# header_checker.py
# checks HTTP response headers for missing or misconfigured security headers
# you'd be shocked how many sites just... don't have these. big smh energy.

import requests


# headers we're checking for and why they matter
# spent way too long reading MDN docs for this list ngl
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Forces HTTPS. Without this, MITM attacks are way easier.',
        'severity': 'HIGH',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'Content-Security-Policy': {
        'description': 'Controls what resources the browser can load. Massive XSS mitigation.',
        'severity': 'HIGH',
        'recommendation': 'Add a CSP header. Even a basic one helps: Content-Security-Policy: default-src \'self\''
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks by blocking iframe embedding.',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes)'
    },
    'X-Content-Type-Options': {
        'description': 'Stops browsers from MIME-sniffing. Sounds boring, actually important.',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Content-Type-Options: nosniff'
    },
    'Referrer-Policy': {
        'description': 'Controls how much referrer info gets sent with requests.',
        'severity': 'LOW',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'description': 'Controls browser features like camera, mic, geolocation.',
        'severity': 'LOW',
        'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS filter for old browsers. Mostly deprecated but still worth noting.',
        'severity': 'LOW',
        'recommendation': 'Add: X-XSS-Protection: 1; mode=block (old browsers only tbh)'
    },
}

# headers that are present but maybe leaking too much info
# "hey i'm running Apache 2.4.1 with PHP 5.6" is not information you wanna share lol
INFO_LEAK_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']


class HeaderChecker:
    def __init__(self, timeout=5, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            'missing': [],
            'present': [],
            'info_leaks': [],
            'grade': 'A'  # starts optimistic, gets worse from here lol
        }

    def check(self, url):
        """
        fires a GET request and inspects the response headers
        returns a full report dict with missing headers + info leaks
        """
        print(f"\n[*] checking security headers on {url}")

        try:
            response = requests.get(url, timeout=self.timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            headers = response.headers

            # check each expected security header
            for header_name, info in SECURITY_HEADERS.items():
                if header_name in headers:
                    self.results['present'].append({
                        'header': header_name,
                        'value': headers[header_name],
                        'description': info['description']
                    })
                    if self.verbose:
                        print(f"  [+] {header_name}: present")
                else:
                    self.results['missing'].append({
                        'header': header_name,
                        'severity': info['severity'],
                        'description': info['description'],
                        'recommendation': info['recommendation']
                    })
                    print(f"  [-] MISSING: {header_name} ({info['severity']})")

            # check for info-leaking headers
            # these aren't vuln per se, but they give attackers a roadmap smh
            for leak_header in INFO_LEAK_HEADERS:
                if leak_header in headers:
                    self.results['info_leaks'].append({
                        'header': leak_header,
                        'value': headers[leak_header],
                        'note': 'Consider removing or obfuscating this - it reveals server info'
                    })
                    print(f"  [~] info leak: {leak_header}: {headers[leak_header]}")

            # calculate a grade cuz why not, makes the report look pro
            self.results['grade'] = self._calculate_grade()
            print(f"\n  [*] security header grade: {self.results['grade']}")
            return self.results

        except requests.exceptions.ConnectionError:
            print(f"  [!] couldn't connect to {url}")
            return None
        except requests.exceptions.Timeout:
            print(f"  [!] request timed out on {url}")
            return None
        except Exception as e:
            print(f"  [!] something went wrong: {e}")
            return None

    def _calculate_grade(self):
        """
        gives a letter grade based on missing headers
        totally made up scoring system but it looks official so we keep it
        """
        missing = self.results['missing']
        high_missing = sum(1 for m in missing if m['severity'] == 'HIGH')
        medium_missing = sum(1 for m in missing if m['severity'] == 'MEDIUM')

        if high_missing == 0 and medium_missing == 0:
            return 'A'
        elif high_missing == 0 and medium_missing == 1:
            return 'B'
        elif high_missing == 1:
            return 'C'
        elif high_missing == 2:
            return 'D'
        else:
            # this is bad. like, really bad.
            return 'F'
