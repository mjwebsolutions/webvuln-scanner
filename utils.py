# utils.py
# just some helper stuff i kept needing everywhere so i threw it here
# classic move honestly

import re
from urllib.parse import urlparse


def is_valid_url(url):
    """
    checks if a url is actually a url and not just vibes
    bruh you'd be surprised how many people pass garbage into this
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False


def normalize_url(url):
    """
    makes sure the url has http:// or https:// 
    cuz people always forget it and then everything breaks smh
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')


def extract_domain(url):
    """just grab the domain, nothing fancy"""
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(base_url, link):
    """
    make sure we don't accidentally start scanning google.com
    that would be bad. very bad. don't do that lol
    """
    base_domain = extract_domain(base_url)
    link_domain = extract_domain(link)
    return base_domain == link_domain


def clean_url(url):
    """strip fragments and stuff we don't need"""
    # fragments (#section) are useless for scanning, ditch em
    url = re.sub(r'#.*$', '', url)
    return url.strip()


def load_payloads(filepath):
    """
    reads payloads from a file, one per line
    skips blank lines cuz those do nothing obviously
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # filter out empty lines, don't wanna send blank requests fr
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] bruh the payload file doesn't exist: {filepath}")
        return []


def load_wordlist(filepath):
    """same as load_payloads basically, just for wordlists"""
    return load_payloads(filepath)


def truncate(text, max_len=80):
    """
    truncates long strings for clean terminal output
    nobody wants to see a 500 char line scroll by lol
    """
    if len(text) > max_len:
        return text[:max_len] + '...'
    return text
