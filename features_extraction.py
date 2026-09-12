from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter
import math
import re
import ipaddress

def entropy(s):
    """
    Calculate the Shannon entropy of a string.

    Higher entropy means the string contains a more varied or
    less predictable distribution of characters. Random-looking
    domains or URL parameters can sometimes be associated with
    automatically generated or suspicious URLs.
    """
    if not s:
        return 0.0

    counts = Counter(s)
    length = len(s)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

def is_ip(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.

    Returns:
        1 -> hostname is an IP address
        0 -> hostname is not an IP address
    """
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0

def get_ip_version(hostname):
    """
    Determine the IP version of a hostname.

    Returns:
        4 -> IPv4 address
        6 -> IPv6 address
        0 -> hostname is not an IP address
    """
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.version
    except ValueError:
        return 0

def extract_features(url):
    """
    Extract numerical features from a URL.

    These features can be used as input to a machine-learning
    model for phishing URL detection.

    Args:
        url (str): URL to analyze.

    Returns:
        dict: Dictionary containing numerical URL features.
    """

    # =========================================================
    # 1. Basic URL parsing
    # =========================================================

    url = str(url).strip()

    try:
        parsed = urlparse(url)
    except ValueError:
        # If the URL cannot be parsed, use an empty URL instead.
        parsed = urlparse('')

    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # Lowercase versions make keyword and pattern matching
    # case-insensitive.
    url_lower = url.lower()
    hostname_lower = hostname.lower()
    path_lower = path.lower()
    query_lower = query.lower()

    # Decode percent-encoded characters such as %2F or %40.
    decoded_url = unquote(url_lower)

    # =========================================================
    # 2. Suspicious words
    # =========================================================

    # Phishing URLs often contain words designed to create urgency
    # or imitate legitimate authentication/account processes.
    suspicious_words = [
        'login', 'log-in',
        'signin', 'sign-in',
        'verify', 'verification',
        'account',
        'secure', 'security',
        'update',
        'confirm', 'confirmation',
        'password', 'passwd',
        'wallet',
        'payment',
        'billing',
        'invoice',
        'authenticate', 'authentication',
        'credential', 'credentials',
        'recover', 'recovery',
        'unlock',
        'suspend', 'suspended',
        'validate', 'validation'
    ]

    # Count how many different suspicious terms occur in the URL.
    num_suspicious_words = sum(
        word in url_lower
        for word in suspicious_words
    )

    # =========================================================
    # 3. Query parameters
    # =========================================================

    # Query parameters can contain useful information such as
    # redirect destinations, tracking IDs, or encoded data.
    try:
        query_params = parse_qs(query)
    except ValueError:
        query_params = {}

    # =========================================================
    # 4. Domain components
    # =========================================================

    domain_parts = hostname.split('.') if hostname else []

    # Approximate number of subdomains.
    #
    # Example:
    #     login.secure.example.com
    #
    # Domain parts = [login, secure, example, com]
    # Approximate subdomains = 2
    #
    # NOTE:
    # This is a simple approximation and does not correctly handle
    # every public suffix, such as "co.uk".
    num_subdomains = max(0, len(domain_parts) - 2)

    # Approximate registered/second-level domain.
    if len(domain_parts) >= 2:
        registered_domain = '.'.join(domain_parts[-2:])
    elif domain_parts:
        registered_domain = domain_parts[0]
    else:
        registered_domain = ''

    # =========================================================
    # 5. Character statistics
    # =========================================================

    # Number of digits anywhere in the URL.
    num_digits = sum(c.isdigit() for c in url)

    # Number of alphabetic characters.
    num_letters = sum(c.isalpha() for c in url)

    # Count characters that are neither letters/numbers nor
    # common URL separators.
    num_special_chars = sum(
        1
        for c in url
        if not c.isalnum() and c not in ['.', '/', ':']
    )

    # Count percent-encoded bytes such as:
    #     %20
    #     %2F
    #     %40
    num_encoded_chars = len(
        re.findall(r'%[0-9a-fA-F]{2}', url)
    )

    # =========================================================
    # 6. Suspicious URL patterns
    # =========================================================

    # An '@' can be abused to make a URL appear to belong to
    # one domain while the actual hostname appears after '@'.
    #
    # Example:
    #     https://google.com@malicious-site.com
    has_at = int('@' in url)

    # Double slashes inside the path can sometimes be suspicious.
    has_double_slash_path = int('//' in path)

    # Explicit username/password information in the network
    # location.
    #
    # Example:
    #     https://username:password@example.com
    has_userinfo = int('@' in parsed.netloc)

    # Long sequences of digits in a hostname may indicate
    # automatically generated or suspicious domains.
    has_long_digit_sequence = int(
        bool(re.search(r'\d{5,}', hostname))
    )

    # Multiple hyphens in a hostname can be an indicator of
    # artificially constructed domain names.
    has_multiple_hyphens = int(
        hostname.count('-') >= 2
    )

    # =========================================================
    # 7. File extension and download indicators
    # =========================================================

    # File types that may be associated with executable content.
    dangerous_extensions = [
        '.exe',
        '.scr',
        '.bat',
        '.cmd',
        '.com',
        '.pif',
        '.msi',
        '.jar'
    ]

    has_dangerous_extension = int(
        any(
            ext in path_lower
            for ext in dangerous_extensions
        )
    )

    # Check specifically for .exe.
    has_exe = int('.exe' in url_lower)

    # PHP is common on legitimate websites, but can also occur
    # in phishing pages.
    has_php = int('.php' in url_lower)

    # Words associated with downloading or installing software.
    has_download = int(
        any(
            word in url_lower
            for word in [
                'download',
                'install',
                'setup'
            ]
        )
    )

    # =========================================================
    # 8. Brand impersonation indicators
    # =========================================================

    # Common brands that are frequently impersonated in phishing
    # attacks.
    brand_words = [
        'google',
        'microsoft',
        'apple',
        'amazon',
        'paypal',
        'facebook',
        'instagram',
        'linkedin',
        'netflix',
        'bank'
    ]

    # Count the number of brand-related words appearing anywhere
    # in the URL.
    num_brand_words = sum(
        word in url_lower
        for word in brand_words
    )

    # Check whether a brand name appears in a subdomain.
    #
    # Example:
    #     microsoft.malicious-site.com
    #
    # The presence of "microsoft" as a subdomain does not mean
    # the site belongs to Microsoft.
    brand_in_subdomain = int(
        any(
            brand in hostname_lower.split('.')[:-2]
            for brand in brand_words
        )
    )

    # =========================================================
    # 9. Entropy features
    # =========================================================

    # Entropy measures how unpredictable the characters are.
    #
    # High entropy can sometimes indicate randomly generated
    # domains, paths, or query parameters.
    url_entropy = entropy(url)
    domain_entropy = entropy(hostname)
    path_entropy = entropy(path)
    query_entropy = entropy(query)

    # =========================================================
    # 10. Build feature dictionary
    # =========================================================

    features = {

        # -----------------------------------------------------
        # Basic URL measurements
        # -----------------------------------------------------

        # Total length of the URL.
        'url_length': len(url),

        # Length of the hostname/domain.
        'domain_length': len(hostname),

        # Length of the URL path.
        'path_length': len(path),

        # Length of the query string.
        'query_length': len(query),

        # -----------------------------------------------------
        # Protocol
        # -----------------------------------------------------

        # HTTPS is generally safer than HTTP, although HTTPS
        # alone does NOT prove that a website is legitimate.
        'has_https': int(
            parsed.scheme.lower() == 'https'
        ),

        # -----------------------------------------------------
        # URL character statistics
        # -----------------------------------------------------

        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_slashes': url.count('/'),
        'num_percent': url.count('%'),
        'num_at': url.count('@'),
        'num_colons': url.count(':'),
        'num_digits': num_digits,
        'num_letters': num_letters,
        'num_special_chars': num_special_chars,

        # -----------------------------------------------------
        # Domain characteristics
        # -----------------------------------------------------

        # Number of digits specifically inside the hostname.
        'num_digits_domain': sum(
            c.isdigit()
            for c in hostname
        ),

        # Whether the hostname is an IP address.
        'has_ip': is_ip(hostname),

        # IP version:
        # 0 = not an IP
        # 4 = IPv4
        # 6 = IPv6
        'ip_version': get_ip_version(hostname),

        # Whether the domain contains at least one hyphen.
        'has_dash_domain': int('-' in hostname),

        # Whether the domain contains two or more hyphens.
        'has_multiple_hyphens': has_multiple_hyphens,

        # Approximate number of subdomains.
        'num_subdomains': num_subdomains,

        # Length of the approximate registered domain.
        'registered_domain_length': len(
            registered_domain
        ),

        # -----------------------------------------------------
        # Suspicious URL patterns
        # -----------------------------------------------------

        'has_at': has_at,
        'has_userinfo': has_userinfo,
        'has_double_slash': has_double_slash_path,
        'has_long_digit_sequence': has_long_digit_sequence,

        # Number of percent-encoded characters.
        'num_encoded_chars': num_encoded_chars,

        # 1 if at least one percent-encoded character exists.
        'has_hex_encoding': int(
            num_encoded_chars > 0
        ),

        # -----------------------------------------------------
        # Query characteristics
        # -----------------------------------------------------

        # Number of parsed query parameters.
        'num_query_params': len(query_params),

        # Whether the query contains '='.
        'query_has_equals': int('=' in query),

        # Whether the query contains '&'.
        'query_has_ampersand': int('&' in query),

        # -----------------------------------------------------
        # Entropy
        # -----------------------------------------------------

        'url_entropy': url_entropy,
        'domain_entropy': domain_entropy,
        'path_entropy': path_entropy,
        'query_entropy': query_entropy,

        # -----------------------------------------------------
        # Suspicious vocabulary
        # -----------------------------------------------------

        'num_suspicious_words': num_suspicious_words,

        # -----------------------------------------------------
        # File and download indicators
        # -----------------------------------------------------

        'has_exe': has_exe,
        'has_php': has_php,
        'has_dangerous_extension': (
            has_dangerous_extension
        ),
        'has_download': has_download,

        # -----------------------------------------------------
        # Brand impersonation
        # -----------------------------------------------------

        'num_brand_words': num_brand_words,
        'brand_in_subdomain': brand_in_subdomain,
    }

    return features