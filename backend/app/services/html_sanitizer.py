import re
import logging
from typing import Dict, Any, List, Set
from bs4 import BeautifulSoup
import bleach

logger = logging.getLogger("spectrashield.html_sanitizer")

# Obfuscation zero-width characters used to bypass keyword filters
ZERO_WIDTH_REGEX = re.compile(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060]")

# Event handlers like onload, onerror, onclick, etc.
EVENT_HANDLER_REGEX = re.compile(r"^on[a-zA-Z]+$", re.IGNORECASE)

DANGEROUS_TAGS: Set[str] = {
    "script", "iframe", "object", "embed", "applet",
    "form", "base", "meta", "link", "style"
}

ALLOWED_TAGS = [
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em",
    "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img",
    "li", "ol", "p", "pre", "span", "strong", "table", "tbody",
    "td", "th", "thead", "tr", "u", "ul"
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "*": ["class", "id", "align", "dir"]
}


class HTMLSanitizer:
    """
    Sanitizes untrusted email HTML payloads:
    - Strips executable elements (<script>, <iframe>, <object>, <embed>, <form>)
    - Cleans inline DOM event handlers (onload, onerror, onclick)
    - Strips invisible zero-width Unicode characters used for NLP evasion
    - Collects forensic script cues for threat analysis
    - Normalizes and defangs dangerous hyperlink schemes (javascript:, vbscript:, data:)
    """

    def sanitize(self, raw_html: str) -> Dict[str, Any]:
        """
        Executes strict decoupling and sanitization of raw HTML email body.
        Returns sanitized HTML, script cues, and metadata.
        """
        if not raw_html:
            return {
                "sanitized_html": "",
                "clean_text": "",
                "script_cues": [],
                "has_hidden_scripts": False,
                "zero_width_chars_removed": 0,
                "dangerous_tags_stripped": []
            }

        script_cues: List[str] = []
        dangerous_tags_found: List[str] = []

        # 1. Detect zero-width characters
        zw_matches = ZERO_WIDTH_REGEX.findall(raw_html)
        zw_count = len(zw_matches)
        if zw_count > 0:
            script_cues.append(f"Stripped {zw_count} invisible zero-width evasion character(s)")
            cleaned_html = ZERO_WIDTH_REGEX.sub("", raw_html)
        else:
            cleaned_html = raw_html

        # 2. Inspect with BeautifulSoup to catalog dangerous artifacts before stripping
        try:
            soup = BeautifulSoup(cleaned_html, "html.parser")
            
            # Find dangerous tags
            for tag_name in DANGEROUS_TAGS:
                found_tags = soup.find_all(tag_name)
                if found_tags:
                    dangerous_tags_found.append(tag_name)
                    script_cues.append(f"Dangerous active <{tag_name}> tag detected ({len(found_tags)} instance(s))")

            # Find event attributes
            event_count = 0
            for el in soup.find_all(True):
                attrs = list(el.attrs.keys())
                for attr in attrs:
                    if EVENT_HANDLER_REGEX.match(attr):
                        event_count += 1
                        val = el.attrs.get(attr, "")
                        script_cues.append(f"Inline event attribute '{attr}=\"{val}\"' removed from <{el.name}>")

            # Check for javascript: or data: URIs in href
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag["href"]).strip().lower()
                if href.startswith(("javascript:", "vbscript:", "data:text/html")):
                    script_cues.append(f"Dangerous URI scheme in hyperlink defanged: {href[:40]}")
        except Exception as e:
            logger.debug(f"Pre-sanitization inspection encountered error: {e}")

        # 3. Clean HTML using Bleach with strict allowlist
        try:
            cleaned_html = bleach.clean(
                cleaned_html,
                tags=ALLOWED_TAGS,
                attributes=ALLOWED_ATTRIBUTES,
                strip=True
            )
        except Exception as e:
            logger.warning(f"Bleach sanitization failed: {e}; falling back to text extraction")
            cleaned_html = re.sub(r"<[^>]*>", " ", cleaned_html)

        # 4. Extract safe readable plain text
        try:
            clean_soup = BeautifulSoup(cleaned_html, "html.parser")
            clean_text = clean_soup.get_text(separator=" ", strip=True)
        except Exception:
            clean_text = re.sub(r"<[^>]*>", " ", cleaned_html).strip()

        has_hidden_scripts = len(script_cues) > 0 or len(dangerous_tags_found) > 0

        return {
            "sanitized_html": cleaned_html,
            "clean_text": clean_text,
            "script_cues": script_cues,
            "has_hidden_scripts": has_hidden_scripts,
            "zero_width_chars_removed": zw_count,
            "dangerous_tags_stripped": dangerous_tags_found
        }


html_sanitizer = HTMLSanitizer()
