# dir_bruteforce.py
# tries common directory/file names against the target
# basically just guessing, but educated guessing with a wordlist lol
# this is super common in real pentests, nothing fancy

import requests
from src.utils import load_wordlist


class DirBruteforcer:
    def __init__(self, wordlist="wordlists/common_dirs.txt", timeout=5, verbose=False):
        self.wordlist = load_wordlist(wordlist)
        self.timeout = timeout
        self.verbose = verbose
        self.found = []

        if not self.wordlist:
            print("[!] wordlist is empty, dir bruteforce won't do much fam")

    def scan(self, base_url):
        """
        tries every word in the wordlist as a path on the target
        200 = found it, 403 = exists but blocked, 301/302 = redirect (also interesting)
        404 = nothing there, we move
        """
        print(f"\n[*] starting directory bruteforce on {base_url}")
        print(f"[*] trying {len(self.wordlist)} paths... grab a coffee lol")

        base_url = base_url.rstrip('/')

        for word in self.wordlist:
            url = f"{base_url}/{word}"
            try:
                # stream=False just means we don't download the whole body
                # we only care about the status code here, saves bandwidth
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,  # catch redirects separately
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                )

                status = response.status_code

                if status == 200:
                    print(f"  [+] FOUND [{status}] {url}")
                    self.found.append({'url': url, 'status': status, 'note': 'accessible'})

                elif status in (301, 302):
                    redirect_to = response.headers.get('Location', 'unknown')
                    print(f"  [~] REDIRECT [{status}] {url} -> {redirect_to}")
                    self.found.append({'url': url, 'status': status, 'note': f'redirects to {redirect_to}'})

                elif status == 403:
                    # exists but we can't get in - still worth logging
                    if self.verbose:
                        print(f"  [~] FORBIDDEN [{status}] {url} - exists but blocked")
                    self.found.append({'url': url, 'status': status, 'note': 'exists but forbidden'})

                else:
                    # 404 and everything else, we don't care
                    if self.verbose:
                        print(f"  [-] [{status}] {url}")

            except requests.exceptions.Timeout:
                if self.verbose:
                    print(f"  [!] timeout on {url}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    print(f"  [!] connection refused for {url}")
            except Exception as e:
                if self.verbose:
                    print(f"  [!] error on {url}: {e}")

        accessible = [f for f in self.found if f['status'] == 200]
        print(f"\n[+] dir bruteforce done. found {len(accessible)} accessible path(s)")
        return self.found
