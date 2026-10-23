"""
SSRF Protection and Safe URL Inspector for ScamShield.
Defends against Server-Side Request Forgery, DNS rebinding, private IP attacks,
homograph/lookalike character spoofing, userinfo obfuscation, and dangerous schemes.
"""
import ipaddress
import re
import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, unquote


# Known dangerous and private network CIDR blocks
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (Cloud metadata e.g. AWS/GCP 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "buzz", "cam", "fit", "gq", "cf", "ga", "ml", "tk",
    "work", "loan", "men", "country", "stream", "download", "racing", "win",
    "review", "party", "trade", "accountant", "bid", "date", "faith", "cricket"
}

# Common high-value brands targeted by homographs and lookalikes
TARGET_BRANDS = {
    "google": ["g00gle", "googie", "goog1e", "goolge"],
    "apple": ["app1e", "appl-e", "apple-id", "appleid"],
    "paypal": ["paypa1", "pay-pal", "paypai", "paypa-l"],
    "microsoft": ["micros0ft", "m1crosoft", "micro-soft"],
    "amazon": ["amaz0n", "arnazon", "amazn"],
    "netflix": ["netf1ix", "net-flix", "netfllx"],
    "chase": ["chas-e", "chase-bank", "chas0"],
    "wellsfargo": ["wells-fargo", "wellsfarg0"],
    "bankofamerica": ["bankofamer1ca", "bank-of-america", "bofa-secure"],
    "facebook": ["faceb00k", "face-book"],
    "instagram": ["1nstagram", "instagrarn"],
    "whatsapp": ["whats-app", "whatsap"],
}

# Cyrillic / Greek homoglyphs commonly substituted for Latin characters
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', 'υ': 'u', 'ν': 'v', 'ω': 'w',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b',
}

OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_to", "next", "return", "return_to",
    "goto", "target", "dest", "destination", "out", "r", "u", "link"
}


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to any private, loopback, or cloud-metadata network."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return any(ip in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_ip_host(hostname: str) -> bool:
    """Detect if hostname is an IPv4, IPv6, or obfuscated numeric IP (octal, hex, dword)."""
    cleaned = hostname.strip("[]")
    # Standard IPv4 or IPv6
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        pass

    # Obfuscated numeric IPv4: single large integer (dword), hex format, or octal format
    if cleaned.isdigit() and int(cleaned) > 0:
        return True
    if cleaned.lower().startswith("0x"):
        try:
            int(cleaned, 16)
            return True
        except ValueError:
            pass

    return False


def check_homograph_and_lookalike(hostname: str) -> Dict[str, Any]:
    """Detect punycode (IDN) or lookalike substitutions targeting trusted brands."""
    findings = []
    is_lookalike = False
    target_brand = None

    # Punycode check
    if "xn--" in hostname.lower():
        try:
            decoded = hostname.encode("ascii").decode("idna")
            findings.append(f"Punycode/IDN internationalized domain detected: decodes to '{decoded}'")
            is_lookalike = True
        except Exception:
            findings.append("Malformed or suspicious Punycode/IDN prefix detected")
            is_lookalike = True

    # Character normalization check
    normalized = hostname.lower()
    for char, rep in HOMOGLYPH_MAP.items():
        if char in normalized:
            normalized = normalized.replace(char, rep)
            findings.append(f"Suspicious character or zero-width/homoglyph '{char}' substituted for '{rep}'")
            is_lookalike = True

    # Brand target spoofing
    lower_host = hostname.lower()
    for brand, lookalikes in TARGET_BRANDS.items():
        if brand in lower_host and not lower_host.endswith(f".{brand}.com") and not lower_host == f"{brand}.com":
            findings.append(f"Domain contains trusted brand name '{brand}' in an unauthorized pattern: {hostname}")
            is_lookalike = True
            target_brand = brand
        for lk in lookalikes:
            if lk in lower_host:
                findings.append(f"Domain contains typosquatted or lookalike string '{lk}' for '{brand}'")
                is_lookalike = True
                target_brand = brand

    return {
        "is_lookalike": is_lookalike,
        "target_brand": target_brand,
        "details": findings,
    }


def analyze_safe_url(raw_url: str) -> Dict[str, Any]:
    """
    Safely inspect a URL without performing outbound HTTP network calls.
    Returns deterministic security checks, SSRF flags, and suspicious indicators.
    """
    results: Dict[str, Any] = {
        "raw_url": raw_url,
        "is_valid_syntax": True,
        "scheme": None,
        "is_https": False,
        "hostname": None,
        "port": None,
        "is_ip_host": False,
        "is_private_ssrf": False,
        "has_userinfo": False,
        "userinfo": None,
        "homograph_check": {},
        "subdomain_depth": 0,
        "suspicious_tld": False,
        "tld": None,
        "open_redirect_params": [],
        "obfuscation_detected": False,
        "warnings": [],
        "severity": "LOW",
        "risk_points": 0,
    }

    url_to_parse = raw_url.strip()
    # Add scheme if missing for safe parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_to_parse):
        url_to_parse = "https://" + url_to_parse
        results["warnings"].append("No scheme provided; defaulted to https for parsing.")

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        results["is_valid_syntax"] = False
        results["warnings"].append(f"Invalid URL syntax: {str(e)}")
        results["severity"] = "HIGH"
        results["risk_points"] += 40
        return results

    results["scheme"] = parsed.scheme.lower() if parsed.scheme else None
    results["hostname"] = parsed.hostname.lower() if parsed.hostname else None
    results["port"] = parsed.port

    # 1. Scheme Validation
    if results["scheme"] not in ["http", "https"]:
        results["warnings"].append(f"Dangerous or non-web scheme detected: '{results['scheme']}' (risk of local protocol handler abuse)")
        results["risk_points"] += 50
        results["severity"] = "HIGH"
    elif results["scheme"] == "http":
        results["is_https"] = False
        results["warnings"].append("Insecure plain HTTP protocol in use (data transmitted in unencrypted plaintext)")
        results["risk_points"] += 15
    else:
        results["is_https"] = True

    if not results["hostname"]:
        results["is_valid_syntax"] = False
        results["warnings"].append("No valid hostname found in URL")
        results["risk_points"] += 40
        results["severity"] = "HIGH"
        return results

    # 2. Userinfo Obfuscation Check (e.g. https://google.com@evil-site.com)
    if parsed.username or parsed.password:
        results["has_userinfo"] = True
        results["userinfo"] = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
        results["warnings"].append(
            f"URL contains embedded userinfo ('{results['userinfo']}@'). This is a classic phishing technique to disguise the real destination domain!"
        )
        results["risk_points"] += 45
        results["obfuscation_detected"] = True

    # 3. IP Address Hostname & SSRF Check
    hostname = results["hostname"]
    if is_ip_host(hostname):
        results["is_ip_host"] = True
        results["risk_points"] += 35
        results["warnings"].append(f"Direct IP address host used instead of registered domain: {hostname}")

        # Check if it targets internal/private/cloud metadata IP (SSRF)
        clean_ip = hostname.strip("[]")
        if is_private_or_restricted_ip(clean_ip):
            results["is_private_ssrf"] = True
            results["risk_points"] += 60
            results["warnings"].append(
                f"CRITICAL: Target IP '{clean_ip}' is within private/internal/cloud metadata range (SSRF defense triggered)"
            )
            results["severity"] = "CRITICAL"

    # 4. Homograph & Punycode Lookalikes
    homograph_res = check_homograph_and_lookalike(hostname)
    results["homograph_check"] = homograph_res
    if homograph_res["is_lookalike"]:
        results["risk_points"] += 40
        for detail in homograph_res["details"]:
            results["warnings"].append(detail)

    # 5. Subdomain Structure & TLD Analysis
    parts = hostname.split(".")
    results["subdomain_depth"] = len(parts)
    if len(parts) >= 4 and not results["is_ip_host"]:
        results["warnings"].append(f"Unusually deep subdomain hierarchy ({len(parts)} levels) often used to hide the primary domain")
        results["risk_points"] += 20

    if len(parts) >= 2:
        tld = parts[-1].lower()
        results["tld"] = tld
        if tld in SUSPICIOUS_TLDS:
            results["suspicious_tld"] = True
            results["warnings"].append(f"Domain uses high-abuse top-level domain '.{tld}'")
            results["risk_points"] += 25

    # 6. Non-standard Ports
    if results["port"] and results["port"] not in [80, 443, 8080, 8443]:
        results["warnings"].append(f"Unusual web port :{results['port']} specified in URL")
        results["risk_points"] += 15

    # 7. Open Redirect Parameters
    if parsed.query:
        query_params = parse_qs(parsed.query)
        for param, vals in query_params.items():
            if param.lower() in OPEN_REDIRECT_PARAMS:
                for val in vals:
                    if val.startswith("http://") or val.startswith("https://") or val.startswith("//"):
                        results["open_redirect_params"].append({"param": param, "target": val})
                        results["warnings"].append(
                            f"Suspicious open redirect parameter '{param}={val}' detected (may bounce user to third-party phishing site)"
                        )
                        results["risk_points"] += 30

    # 8. Path obfuscation & Hex encoding
    if "%" in parsed.path or "%" in (parsed.query or ""):
        decoded_path = unquote(parsed.path)
        if decoded_path != parsed.path:
            results["warnings"].append("URL contains URL-encoded escape characters in path or parameters")
            results["risk_points"] += 10

    # Determine severity
    if results["is_private_ssrf"] or results["risk_points"] >= 80:
        results["severity"] = "CRITICAL"
    elif results["risk_points"] >= 50:
        results["severity"] = "HIGH"
    elif results["risk_points"] >= 25:
        results["severity"] = "MODERATE"
    else:
        results["severity"] = "LOW"

    return results
