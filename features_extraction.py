from urllib.parse import urlparse
import re


def extract_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {
        # Basic structural features
        'url_length': len(url),  # Total length of the URL
        'domain_length': len(netloc),  # Length of the domain
        'path_length': len(path),  # Length of the URL path
        'query_length': len(query),  # Length of the query string

        # Protocol
        'has_https': int(parsed.scheme == 'https'),  # 1 if HTTPS is used, 0 otherwise

        # Character and symbol analysis
        'num_dots': url.count('.'),  # Number of dot characters
        'num_hyphens': url.count('-'),  # Number of hyphens in the URL
        'num_underscores': url.count('_'),  # Number of underscores
        'num_slashes': url.count('/'),  # Number of forward slashes
        'num_percent': url.count('%'),  # Percent-encoding often used in obfuscated URLs
        'num_at': url.count('@'),  # Presence of '@' symbol (may hide actual domain)
        'num_colons': url.count(':'),  # Number of colon characters
        'num_digits': sum(c.isdigit() for c in url),  # Total number of digit characters
        'num_special_chars': sum(1 for c in url if not c.isalnum() and c not in ['.', '/', ':']),  # Non-alphanumeric special characters

        # Structural red flags
        'has_ip': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc))),  # If domain is an IP address
        'has_at': int('@' in url),  # 1 if '@' is used
        'has_dash': int('-' in netloc),  # 1 if dash is in domain (can be suspicious)

        # Subdomain analysis
        'num_subdomains': netloc.count('.') - 1 if not re.match(r'^\d+\.\d+\.\d+\.\d+$', netloc) else 0,  # Number of subdomains (excluding IPs)

        # Presence of suspicious keywords (expandable list)
        'has_login': int('login' in url.lower()),
        'has_secure': int('secure' in url.lower()),
        'has_account': int('account' in url.lower()),
        'has_update': int('update' in url.lower()),
        'has_verify': int('verify' in url.lower()),
        'has_bank': int('bank' in url.lower()),

        # TLD and file extension
        'tld_length': len(netloc.split('.')[-1]) if '.' in netloc else 0,
        'has_exe': int('.exe' in url.lower()),  # Suspicious file extension
        'has_php': int('.php' in url.lower()),  # Common in dynamic (and sometimes malicious) URLs
    }

    return features