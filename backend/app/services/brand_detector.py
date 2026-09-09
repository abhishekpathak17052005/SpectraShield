import unicodedata
from typing import Dict, List, Any, Optional

try:
    import idna
except ImportError:
    idna = None

known_brands = {
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "sbi": "sbi.co.in",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "facebook": "facebook.com",
    "meta": "meta.com",
    "linkedin": "linkedin.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "dropbox": "dropbox.com"
}

# Unicode Homoglyphs (Cyrillic & Greek lookalikes commonly exploited in typosquatting)
HOMOGLYPH_LOOKALIKES = {
    # Cyrillic small
    '\u0430': ('a', 'CYRILLIC SMALL LETTER A', 'Cyrillic'),
    '\u0441': ('c', 'CYRILLIC SMALL LETTER ES', 'Cyrillic'),
    '\u0435': ('e', 'CYRILLIC SMALL LETTER IE', 'Cyrillic'),
    '\u0456': ('i', 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I', 'Cyrillic'),
    '\u0458': ('j', 'CYRILLIC SMALL LETTER JE', 'Cyrillic'),
    '\u043E': ('o', 'CYRILLIC SMALL LETTER O', 'Cyrillic'),
    '\u0440': ('p', 'CYRILLIC SMALL LETTER ER', 'Cyrillic'),
    '\u0455': ('s', 'CYRILLIC SMALL LETTER DZE', 'Cyrillic'),
    '\u0445': ('x', 'CYRILLIC SMALL LETTER HA', 'Cyrillic'),
    '\u0443': ('y', 'CYRILLIC SMALL LETTER U', 'Cyrillic'),
    # Cyrillic capital
    '\u0410': ('A', 'CYRILLIC CAPITAL LETTER A', 'Cyrillic'),
    '\u0412': ('B', 'CYRILLIC CAPITAL LETTER VE', 'Cyrillic'),
    '\u0415': ('E', 'CYRILLIC CAPITAL LETTER IE', 'Cyrillic'),
    '\u041A': ('K', 'CYRILLIC CAPITAL LETTER KA', 'Cyrillic'),
    '\u041C': ('M', 'CYRILLIC CAPITAL LETTER EM', 'Cyrillic'),
    '\u041D': ('H', 'CYRILLIC CAPITAL LETTER EN', 'Cyrillic'),
    '\u041E': ('O', 'CYRILLIC CAPITAL LETTER O', 'Cyrillic'),
    '\u0420': ('P', 'CYRILLIC CAPITAL LETTER ER', 'Cyrillic'),
    '\u0421': ('C', 'CYRILLIC CAPITAL LETTER ES', 'Cyrillic'),
    '\u0422': ('T', 'CYRILLIC CAPITAL LETTER TE', 'Cyrillic'),
    '\u0425': ('X', 'CYRILLIC CAPITAL LETTER HA', 'Cyrillic'),
    # Greek small
    '\u03B1': ('a', 'GREEK SMALL LETTER ALPHA', 'Greek'),
    '\u03B5': ('e', 'GREEK SMALL LETTER EPSILON', 'Greek'),
    '\u03B9': ('i', 'GREEK SMALL LETTER IOTA', 'Greek'),
    '\u03BF': ('o', 'GREEK SMALL LETTER OMICRON', 'Greek'),
    '\u03C1': ('p', 'GREEK SMALL LETTER RHO', 'Greek'),
}


# Leetspeak mappings commonly used in spoofing (e.g., g00gle, micros0ft)
LEET_LOOKALIKES = {
    '0': ('o', 'DIGIT ZERO (LEET O)', 'Leetspeak'),
    '1': ('l', 'DIGIT ONE (LEET L/I)', 'Leetspeak'),
    '3': ('e', 'DIGIT THREE (LEET E)', 'Leetspeak'),
    '4': ('a', 'DIGIT FOUR (LEET A)', 'Leetspeak'),
    '5': ('s', 'DIGIT FIVE (LEET S)', 'Leetspeak'),
    '8': ('b', 'DIGIT EIGHT (LEET B)', 'Leetspeak'),
    '@': ('a', 'AT SIGN (LEET A)', 'Leetspeak'),
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_brand_impersonation(text: str, sender_email: str) -> float:
    """Heritage 1.0 brand impersonation heuristic score (0 - 100)."""
    text = text.lower()
    score = 0.0

    for brand, domain in known_brands.items():
        if brand in text:
            if sender_email and domain not in sender_email.lower():
                score += 50.0

    return min(score, 100.0)


def check_brand_impersonation_details(text: str, sender_email: str, sender_name: str = "") -> Dict[str, Any]:
    """Evaluates if text or display name mimics a known brand while sending from an external domain."""
    combined = (f"{sender_name} {text}").lower()
    sender_lower = (sender_email or "").lower()
    sender_domain = sender_lower.split("@")[-1].rstrip(">").strip() if "@" in sender_lower else sender_lower
    impersonated = []

    for brand, legit_domain in known_brands.items():
        if brand in combined:
            if sender_domain and legit_domain not in sender_domain:
                impersonated.append({
                    "brand": brand,
                    "legit_domain": legit_domain,
                    "sender_domain": sender_domain
                })

    return {
        "is_impersonation": len(impersonated) > 0,
        "brands": impersonated,
        "score": 50.0 if impersonated else 0.0
    }


def analyze_homoglyphs(domain_or_email: str) -> Dict[str, Any]:
    """
    Detects Unicode Cyrillic/Greek homoglyphs, Punycode lookalike, and leetspeak domain spoofing (INT-02).
    Returns character-by-character substitution diffs with Unicode hex points and target brand mapping.
    """
    if not domain_or_email:
        return {
            "has_homoglyphs": False,
            "is_punycode": False,
            "raw_domain": "",
            "punycode_ascii": None,
            "normalized_ascii": "",
            "target_brand": None,
            "target_domain": None,
            "substituted_characters": [],
            "risk_score_modifier": 0.0,
            "verdict": "Clean"
        }

    # Extract bare domain if an email address is passed
    target = domain_or_email.strip().lower()
    if "@" in target:
        target = target.split("@")[-1].rstrip(">").strip()
    if "://" in target:
        target = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    else:
        target = target.split("/", 1)[0].split(":", 1)[0]

    raw_domain = target
    is_punycode = False
    decoded_unicode = raw_domain
    punycode_ascii = None

    # Handle Punycode (xn--)
    if "xn--" in raw_domain:
        is_punycode = True
        punycode_ascii = raw_domain
        if idna:
            try:
                decoded_unicode = idna.decode(raw_domain)
            except Exception:
                decoded_unicode = raw_domain
    else:
        # Check if non-ASCII characters exist and compute punycode
        has_non_ascii = any(ord(c) > 127 for c in raw_domain)
        if has_non_ascii and idna:
            try:
                punycode_ascii = idna.encode(raw_domain).decode("ascii")
                is_punycode = True
            except Exception:
                pass

    substituted_chars = []
    normalized_chars = []

    for idx, char in enumerate(decoded_unicode):
        if char in HOMOGLYPH_LOOKALIKES:
            latin_char, char_name, script = HOMOGLYPH_LOOKALIKES[char]
            substituted_chars.append({
                "index": idx,
                "raw_char": char,
                "lookalike_char": latin_char,
                "unicode_hex": f"U+{ord(char):04X}",
                "script": script,
                "char_name": char_name
            })
            normalized_chars.append(latin_char)
        elif char in LEET_LOOKALIKES:
            latin_char, char_name, script = LEET_LOOKALIKES[char]
            substituted_chars.append({
                "index": idx,
                "raw_char": char,
                "lookalike_char": latin_char,
                "unicode_hex": f"U+{ord(char):04X}",
                "script": script,
                "char_name": char_name
            })
            normalized_chars.append(latin_char)
        else:
            normalized_chars.append(char)

    normalized_domain = "".join(normalized_chars)
    has_homoglyphs = len(substituted_chars) > 0

    # Match against protected brand catalog
    matched_brand: Optional[str] = None
    matched_domain: Optional[str] = None

    for brand, legit_domain in known_brands.items():
        if brand in normalized_domain:
            if legit_domain != raw_domain:
                matched_brand = brand
                matched_domain = legit_domain
                break

    # If not exact substring, check Levenshtein distance against known brand names
    if not matched_brand:
        domain_stem = normalized_domain.split(".")[0]
        clean_stem = domain_stem.replace("-", "").replace("_", "")
        for brand, legit_domain in known_brands.items():
            if len(brand) >= 4 and _levenshtein_distance(clean_stem, brand) <= 1:
                matched_brand = brand
                matched_domain = legit_domain
                break

    # Calculate risk score modifier
    risk_modifier = 0.0
    verdict = "Clean"
    if has_homoglyphs and matched_brand:
        risk_modifier = 50.0
        verdict = f"Critical Homoglyph Spoofing ({matched_brand.upper()})"
    elif has_homoglyphs:
        risk_modifier = 35.0
        verdict = "Suspicious Mixed-Script / Leetspeak Homoglyph"
    elif matched_brand and matched_domain != raw_domain:
        risk_modifier = 25.0
        verdict = f"Typosquatting Brand Lookalike ({matched_brand.upper()})"

    return {
        "has_homoglyphs": has_homoglyphs,
        "is_punycode": is_punycode,
        "raw_domain": raw_domain,
        "punycode_ascii": punycode_ascii,
        "normalized_ascii": normalized_domain,
        "target_brand": matched_brand,
        "target_domain": matched_domain,
        "substituted_characters": substituted_chars,
        "risk_score_modifier": risk_modifier,
        "verdict": verdict
    }
