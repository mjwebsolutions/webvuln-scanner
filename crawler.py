# crawler.py
# this is where all the link-finding magic happens
# took me a while to get the recursion right ngl, kept crawling forever lol

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from src.utils import is_same_domain, clean_url, is_valid_url


class Crawler:
    def __init__(self, base_url, max_pages=30, timeout=5, verbose=False):
        self.base_url = base_url
        self.max_pages = max_pages  # don't let it go crazy and crawl 10000 pages
        self.timeout = timeout
        self.verbose = verbose
        self.visited = set()
        self.forms = []  # all forms we find get stored here
        self.session = requests.Session()
        self.session.headers.update({
            # look like a normal browser, not some sketchy script
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def crawl(self):
        """
        kicks off the whole crawl from base_url
        returns all unique urls we found + all forms
        """
        print(f"[*] starting crawl on {self.base_url}")
        print(f"[*] max pages set to {self.max_pages} (change if you need more)")
        self._crawl_page(self.base_url)
        print(f"[+] crawl done. visited {len(self.visited)} pages, found {len(self.forms)} forms")
        return list(self.visited), self.forms

    def _crawl_page(self, url):
        """
        recursively visits pages and grabs links + forms
        the recursion limit saved me from an infinite loop situation, 10/10 would add again
        """
        if url in self.visited:
            return
        if len(self.visited) >= self.max_pages:
            # bruh we gotta stop somewhere
            return

        try:
            response = self.session.get(url, timeout=self.timeout)
            self.visited.add(url)

            if self.verbose:
                print(f"  [~] crawling: {url} [{response.status_code}]")

            # only parse html, don't try to parse a pdf or image lol
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # grab all forms on this page, we'll test these for vulns
            page_forms = self._extract_forms(url, soup)
            self.forms.extend(page_forms)

            # find all links and queue em up
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                full_url = clean_url(full_url)

                # only follow links on the same domain, stay in your lane
                if is_valid_url(full_url) and is_same_domain(self.base_url, full_url):
                    if full_url not in self.visited:
                        self._crawl_page(full_url)

        except requests.exceptions.ConnectionError:
            # site said no, that's valid
            if self.verbose:
                print(f"  [!] couldn't connect to {url}, skipping")
        except requests.exceptions.Timeout:
            # took too long, we move
            if self.verbose:
                print(f"  [!] timeout on {url}, skipping")
        except Exception as e:
            # catch everything else cuz the internet is wild
            if self.verbose:
                print(f"  [!] unexpected error on {url}: {e}")

    def _extract_forms(self, page_url, soup):
        """
        pulls out all forms and their input fields from a page
        this info is what we use for injection testing later
        """
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'page_url': page_url,
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }

            # grab every input, select, textarea - anything users can type into
            for tag in form.find_all(['input', 'textarea', 'select']):
                input_type = tag.get('type', 'text')
                input_name = tag.get('name', '')
                input_value = tag.get('value', 'test')  # default val for testing

                # skip submit buttons and hidden fields (usually)
                # actually nah keep hidden fields, sometimes they're interesting
                if input_type == 'submit':
                    continue

                if input_name:
                    form_data['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })

            forms.append(form_data)

        return forms
