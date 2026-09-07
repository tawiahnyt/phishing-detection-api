# Function to calculate "entropy" - a measure of randomness/predictability
# In URL analysis: Legitimate URLs often have predictable patterns (like company names)
# Phishing URLs tend to be more random-looking as scammers generate many variations
# Higher entropy = more random/unpredictable

from urllib.parse import urlparse, parse_qs
from collections import Counter
import math
import re
import ipaddress


def entropy(s):
    if not s:
        return 0

    counts = Counter(s)
    length = len(s)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# Function to check if a hostname is an IP address
# Legitimate websites usually use domain names like "google.com"
# Phishing sites sometimes use raw IP addresses like "192.168.1.1" to look technical
# Returns 1 if it's an IP address, 0 if it's a domain name
def is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


# Main function that examines a URL and extracts 27 different numerical features
# Each feature measures a specific characteristic that might indicate if a URL is safe or dangerous
def extract_features(url):
    try:
        parsed = urlparse(str(url))
    except ValueError:
        parsed = urlparse('')

    hostname = parsed.hostname or ''
    path = parsed.path
    query = parsed.query
    url_lower = str(url).lower()

    # List of words commonly found in phishing URLs that scammers use to trick people
    suspicious_words = [
        'login', 'signin', 'verify', 'verification',
        'account', 'secure', 'update', 'bank',
        'password', 'confirm', 'wallet', 'payment'
    ]

    # Collect all our numerical measurements about this URL
    features = {
        # Basic length measurements - longer URLs can be more suspicious
        'url_length': len(str(url)),                    # Total characters in the URL
        'domain_length': len(hostname),                 # Characters in the website name (like google.com)
        'path_length': len(path),                       # Characters after the domain (/search, /login, etc.)
        'query_length': len(query),                     # Characters in the part after ? (parameters)

        # Security protocol - HTTPS is safer than HTTP
        'has_https': int(parsed.scheme.lower() == 'https'),  # 1 if uses HTTPS, 0 if HTTP

        # Character counts - certain characters appear more often in suspicious URLs
        'num_dots': str(url).count('.'),                # Number of periods
        'num_hyphens': str(url).count('-'),             # Number of dashes
        'num_underscores': str(url).count('_'),         # Number of underscores
        'num_slashes': str(url).count('/'),             # Number of forward slashes
        'num_percent': str(url).count('%'),             # Number of percent signs
        'num_at': str(url).count('@'),                  # Number of @ symbols (often in phishing)
        'num_colons': str(url).count(':'),              # Number of colons
        'num_digits': sum(c.isdigit() for c in str(url)), # Total number of digits

        # Domain-specific measurements
        'num_digits_domain': sum(c.isdigit() for c in hostname), # Digits in the domain name
        'has_ip': is_ip(hostname),                      # Is the domain an IP address? (suspicious)
        'has_dash_domain': int('-' in hostname),        # Does domain contain a dash? (can be suspicious)

        # Subdomain count - more subdomains can sometimes indicate trickery
        'num_subdomains': max(0, len(hostname.split('.')) - 2), # Parts beyond "domain.com"

        # Special characters that aren't normally in URLs
        'num_special_chars': sum(
            1 for c in str(url)
            if not c.isalnum() and c not in ['.', '/', ':']
        ),

        # Specific patterns often seen in phishing
        'has_at': int('@' in str(url)),                 # Contains @ symbol? (very suspicious)
        'has_double_slash': int('//' in path),          # Contains // in the path? (can be suspicious)

        # Query parameters - complex parameter lists can be suspicious
        'num_query_params': len(parse_qs(query)),       # Number of ?parameter=value pairs

        # Randomness measures - legitimate URLs often look less random
        'url_entropy': entropy(str(url)),               # How random/predictable the whole URL is
        'domain_entropy': entropy(hostname),            # How random/predictable just the domain is

        # Content analysis - does it contain suspicious words?
        'num_suspicious_words': sum(
            word in url_lower
            for word in suspicious_words
        ),

        # File extension checks - certain extensions are more risky
        'has_exe': int('.exe' in url_lower),            # Does it try to download an executable?
        'has_php': int('.php' in url_lower),            # Is it a PHP page? (sometimes used in phishing)

        # Top-level domain length - .com, .org, etc. vs unusual ones
        'tld_length': (
            len(hostname.split('.')[-1])
            if '.' in hostname else 0
        ),                                               # Length of .com, .org, .net, etc.
    }

    return features