import re
import base64
import hashlib
import logging
from typing import Dict, Optional, Tuple, Any
import dns.resolver
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger("spectrashield.dkim_verifier")


class StandaloneDkimVerifier:
    """
    Independent DKIM Cryptographic Verification Engine conforming to RFC 6376.
    Resolves raw DNS TXT records directly via dnspython, extracts RSA SubjectPublicKeyInfo,
    canonicalizes body text, and executes mathematical RSA-SHA256 signature verification
    independent of upstream MTA authentication headers.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    def parse_dkim_header(self, dkim_header_str: str) -> Dict[str, str]:
        """Parses semicolon-delimited key=value tags from DKIM-Signature."""
        tags: Dict[str, str] = {}
        # Remove folding whitespace and newlines
        clean_header = re.sub(r'\r?\n\s*', '', dkim_header_str)
        # Split on semicolon followed by tag name
        parts = clean_header.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '=' in part:
                k, v = part.split('=', 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    def query_dns_public_key(self, domain: str, selector: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Directly queries DNS for <selector>._domainkey.<domain> TXT record.
        Returns (is_published, p_base64, raw_txt).
        """
        dns_name = f"{selector}._domainkey.{domain}"
        try:
            answers = self.resolver.resolve(dns_name, "TXT")
            full_txt = ""
            for rdata in answers:
                for chunk in rdata.strings:
                    full_txt += chunk.decode('utf-8', errors='ignore')

            # Parse tags in DNS TXT record
            dns_tags = self.parse_dkim_header(full_txt)
            p_val = dns_tags.get("p")
            return True, p_val, full_txt
        except Exception as e:
            logger.debug(f"DNS lookup failed for {dns_name}: {e}")
            return False, None, None

    def canonicalize_body_relaxed(self, body_text: str) -> bytes:
        """Applies relaxed body canonicalization per RFC 6376 Section 3.4.4."""
        # 1. Reduce all sequences of whitespace within each line to a single space
        lines = body_text.splitlines()
        relaxed_lines = []
        for line in lines:
            # Strip trailing whitespace on each line
            line = re.sub(r'[ \t]+$', '', line)
            # Collapse internal whitespace
            line = re.sub(r'[ \t]+', ' ', line)
            relaxed_lines.append(line)

        # 2. Ignore all empty lines at the end of the message body
        while relaxed_lines and not relaxed_lines[-1]:
            relaxed_lines.pop()

        if not relaxed_lines:
            return b""

        # Return CRLF terminated lines
        return ("\r\n".join(relaxed_lines) + "\r\n").encode("utf-8")

    def verify_dkim(
        self,
        dkim_header_str: str,
        body_text: str = "",
        headers_dict: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Executes full standalone mathematical DKIM verification.
        """
        if not dkim_header_str:
            return {
                "selector": "",
                "signing_domain": "",
                "key_length_bits": 0,
                "algorithm": "NONE",
                "body_hash_valid": False,
                "signature_math_valid": False,
                "dns_key_published": False,
                "raw_public_key": None,
                "verification_status": "NONE",
                "reason": "No DKIM-Signature header present"
            }

        tags = self.parse_dkim_header(dkim_header_str)
        selector = tags.get("s", "")
        domain = tags.get("d", "")
        algo = tags.get("a", "rsa-sha256").lower()
        bh_expected = tags.get("bh", "").strip()
        b_sig = tags.get("b", "").replace(" ", "").replace("\r", "").replace("\n", "").strip()

        if not selector or not domain:
            return {
                "selector": selector,
                "signing_domain": domain,
                "key_length_bits": 0,
                "algorithm": algo,
                "body_hash_valid": False,
                "signature_math_valid": False,
                "dns_key_published": False,
                "raw_public_key": None,
                "verification_status": "FAIL",
                "reason": "Missing mandatory d= or s= tag in DKIM-Signature"
            }

        # 1. Query DNS public key
        dns_published, p_key_b64, raw_dns = self.query_dns_public_key(domain, selector)

        # 2. Body Hash verification
        body_canonical = self.canonicalize_body_relaxed(body_text)
        computed_bh = base64.b64encode(hashlib.sha256(body_canonical).digest()).decode('utf-8')
        body_hash_valid = (computed_bh == bh_expected) if bh_expected else False

        # If DNS lookup did not find record (e.g. offline, test domains)
        if not dns_published or not p_key_b64:
            # If body hash matches, report DNS missing but plausible
            status = "FAIL"
            reason = f"DNS public key not found for {selector}._domainkey.{domain}"
            return {
                "selector": selector,
                "signing_domain": domain,
                "key_length_bits": 0,
                "algorithm": algo,
                "body_hash_valid": body_hash_valid,
                "signature_math_valid": False,
                "dns_key_published": False,
                "raw_public_key": None,
                "verification_status": status,
                "reason": reason
            }

        # 3. Parse RSA Public Key
        try:
            der_bytes = base64.b64decode(p_key_b64)
            pub_key = load_der_public_key(der_bytes)
            key_len = getattr(pub_key, "key_size", 2048)
        except Exception as e:
            return {
                "selector": selector,
                "signing_domain": domain,
                "key_length_bits": 0,
                "algorithm": algo,
                "body_hash_valid": body_hash_valid,
                "signature_math_valid": False,
                "dns_key_published": True,
                "raw_public_key": p_key_b64,
                "verification_status": "FAIL",
                "reason": f"Malformed RSA SubjectPublicKeyInfo: {e}"
            }

        # 4. Verify Mathematical RSA Signature
        signature_math_valid = False
        try:
            sig_bytes = base64.b64decode(b_sig)
            # Reconstruct signed header data representation
            h_tags = [h.strip() for h in tags.get("h", "").split(":") if h.strip()]
            header_lines = []
            if headers_dict:
                for h_name in h_tags:
                    for k, v in headers_dict.items():
                        if k.lower() == h_name.lower():
                            header_lines.append(f"{h_name.lower()}:{v.strip()}")
                            break

            # Add DKIM-Signature header with b= emptied
            clean_dkim = re.sub(r'b=[^;]+', 'b=', dkim_header_str)
            header_lines.append(f"dkim-signature:{clean_dkim.strip()}")
            data_to_verify = "\r\n".join(header_lines).encode("utf-8")

            pub_key.verify(
                sig_bytes,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256() if "sha256" in algo else hashes.SHA1()
            )
            signature_math_valid = True
        except Exception as e:
            logger.debug(f"RSA verification failed: {e}")
            signature_math_valid = False

        if signature_math_valid and body_hash_valid:
            status = "PASS"
            reason = f"RSA-{key_len} Mathematical Signature & Body Hash Verified"
        elif not body_hash_valid:
            status = "FAIL"
            reason = "Cryptographic Body Hash Mismatch (Possible Message Tampering)"
        else:
            status = "FAIL"
            reason = "RSA Signature Mathematical Verification Failed"

        return {
            "selector": selector,
            "signing_domain": domain,
            "key_length_bits": key_len,
            "algorithm": algo,
            "body_hash_valid": body_hash_valid,
            "signature_math_valid": signature_math_valid,
            "dns_key_published": True,
            "raw_public_key": p_key_b64[:32] + "...",
            "verification_status": status,
            "reason": reason
        }


# Global singleton instance
dkim_verifier = StandaloneDkimVerifier()
