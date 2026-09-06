import re
import unicodedata
from typing import Dict, List, Any, Tuple
from app.services.manipulation_detector import calculate_manipulation_score
from app.services.transformer_classifier import transformer_classifier

# Common Homoglyphs (Cyrillic/Greek confusables frequently substituted for ASCII)
_HOMOGLYPH_MAP = {
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j',  # Cyrillic small letter je
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u0443': 'y',  # Cyrillic small letter u
    '\u03bf': 'o',  # Greek small letter omicron
    '\u03c1': 'p',  # Greek small letter rho
}

_ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u200e', '\u200f'}

# Financial & Wire Diversion Patterns
_BEC_FINANCIAL_PATTERNS = [
    re.compile(r'\b(?:wire\s+transfer|direct\s+deposit|bank\s+details|swift\s+code|iban|routing\s+number)\b', re.IGNORECASE),
    re.compile(r'\b(?:invoice\s+attached|unpaid\s+invoice|updated\s+bank\s+account|payment\s+instructions)\b', re.IGNORECASE),
    re.compile(r'\b(?:gift\s+cards?|itunes\s+card|apple\s+gift|steam\s+card|target\s+card)\b', re.IGNORECASE),
    re.compile(r'\b(?:payroll\s+deposit|direct\s+debit|ach\s+transfer|remittance\s+advice)\b', re.IGNORECASE),
    re.compile(r'\b(?:cryptocurrency|bitcoin|btc|usdt|wallet\s+address)\b', re.IGNORECASE),
]

# Executive / VIP Impersonation & Secrecy Cues
_BEC_EXECUTIVE_PATTERNS = [
    re.compile(r'\b(?:are\s+you\s+at\s+your\s+desk|available\s+by\s+email\s+only)\b', re.IGNORECASE),
    re.compile(r'\b(?:in\s+a\s+meeting|cannot\s+take\s+calls?|do\s+not\s+call\s+me)\b', re.IGNORECASE),
    re.compile(r'\b(?:keep\s+this\s+confidential|strictly\s+confidential|between\s+you\s+and\s+me)\b', re.IGNORECASE),
    re.compile(r'\b(?:sent\s+from\s+my\s+iphone|sent\s+from\s+my\s+ipad|sent\s+from\s+mobile)\b', re.IGNORECASE),
    re.compile(r'\b(?:need\s+this\s+done\s+urgently|handle\s+this\s+discreetly|urgent\s+task)\b', re.IGNORECASE),
]

# Credential Harvesting Cues
_CREDENTIAL_PATTERNS = [
    re.compile(r'\b(?:verify\s+your\s+account|validate\s+your\s+mailbox|storage\s+limit\s+exceeded)\b', re.IGNORECASE),
    re.compile(r'\b(?:password\s+expires?\s+today|reset\s+your\s+password|login\s+to\s+keep\s+active)\b', re.IGNORECASE),
    re.compile(r'\b(?:microsoft\s+365\s+security|google\s+workspace\s+alert|it\s+helpdesk\s+notice)\b', re.IGNORECASE),
    re.compile(r'\b(?:action\s+required\s+immediately|unauthorized\s+login\s+attempt|security\s+incident)\b', re.IGNORECASE),
]


class NLPThreatAgent:
    """
    Evaluates email bodies for Business Email Compromise (BEC), executive impersonation,
    financial coercion, zero-width obfuscation, and IDN homoglyph lookalikes.
    """

    def analyze_content(self, text: str, subject: str = "", sender_email: str = "") -> Dict[str, Any]:
        if not text and not subject:
            return self._empty_response()

        full_content = f"{subject}\n{text}".strip()

        # 1. Homoglyph & Obfuscation Analysis
        homoglyphs_detected, clean_text = self._detect_homoglyphs(full_content)
        zero_width_count = sum(full_content.count(ch) for ch in _ZERO_WIDTH_CHARS)

        # 2. Heuristic Manipulation Scoring (Preserved SpectraShield 1.0)
        manipulation_score, flagged_phrases, psych_index = calculate_manipulation_score(clean_text)

        # 3. BEC & Financial Fraud Pattern Matching
        financial_hits = self._scan_patterns(clean_text, _BEC_FINANCIAL_PATTERNS)
        executive_hits = self._scan_patterns(clean_text, _BEC_EXECUTIVE_PATTERNS)
        credential_hits = self._scan_patterns(clean_text, _CREDENTIAL_PATTERNS)

        # 4. Deep Transformer Zero-Shot Intent Classification
        transformer_res = transformer_classifier.classify_intent(clean_text, subject=subject)

        # 5. Executive Display Name VIP Roster Check
        vip_res = transformer_classifier.check_vip_impersonation(sender_email, body_text=clean_text)

        # 6. Synthesize Threat Category & BEC Score
        bec_score, threat_category = self._classify_bec(
            financial_hits=financial_hits,
            executive_hits=executive_hits,
            credential_hits=credential_hits,
            homoglyphs_count=len(homoglyphs_detected),
            manipulation_score=manipulation_score
        )

        all_detected_cues = list(set(financial_hits + executive_hits + credential_hits + flagged_phrases))
        if vip_res.get("is_vip_impersonation"):
            all_detected_cues.append(vip_res["warning"])
            bec_score = max(bec_score, 0.90)
            threat_category = "Executive / VIP Impersonation (Spoofed Display Name)"

        # Overall NLP risk (0 - 100)
        nlp_risk = max(manipulation_score, bec_score * 100.0)
        if homoglyphs_detected or zero_width_count > 0:
            nlp_risk = min(100.0, nlp_risk + 25.0)
        if vip_res.get("is_vip_impersonation"):
            nlp_risk = max(nlp_risk, 92.0)

        return {
            "nlp_risk": round(nlp_risk, 2),
            "bec_score": round(bec_score, 3),
            "threat_category": threat_category,
            "financial_intent": len(financial_hits) > 0,
            "executive_impersonation": len(executive_hits) > 0 or vip_res.get("is_vip_impersonation", False),
            "credential_harvesting": len(credential_hits) > 0,
            "detected_cues": all_detected_cues,
            "psychological_pressure": psych_index,
            "homoglyphs_detected": homoglyphs_detected,
            "zero_width_spaces_detected": zero_width_count,
            "highlighted_phrases": all_detected_cues[:12],
            "transformer_nlp": transformer_res,
            "vip_impersonation": vip_res
        }

    def _detect_homoglyphs(self, text: str) -> Tuple[List[Dict[str, str]], str]:
        detected = []
        clean_chars = []

        for ch in text:
            if ch in _HOMOGLYPH_MAP:
                replacement = _HOMOGLYPH_MAP[ch]
                detected.append({
                    "char": ch,
                    "ascii_equivalent": replacement,
                    "codepoint": f"U+{ord(ch):04X}",
                    "name": unicodedata.name(ch, "UNKNOWN")
                })
                clean_chars.append(replacement)
            elif ch in _ZERO_WIDTH_CHARS:
                continue  # strip zero-width spaces in clean representation
            else:
                clean_chars.append(ch)

        return detected, "".join(clean_chars)

    def _scan_patterns(self, text: str, patterns: List[re.Pattern]) -> List[str]:
        hits = []
        for p in patterns:
            matches = p.findall(text)
            for m in matches:
                clean_m = m.strip()
                if clean_m and clean_m not in hits:
                    hits.append(clean_m)
        return hits

    def _classify_bec(
        self,
        financial_hits: List[str],
        executive_hits: List[str],
        credential_hits: List[str],
        homoglyphs_count: int,
        manipulation_score: float
    ) -> Tuple[float, str]:
        base_bec = 0.0
        threat_category = "Clean / Low Risk"

        if financial_hits and executive_hits:
            base_bec = 0.95
            threat_category = "Business Email Compromise (BEC - Wire Diversion)"
        elif financial_hits:
            base_bec = 0.85
            threat_category = "Financial Fraud / Invoice Redirection"
        elif executive_hits:
            base_bec = 0.78
            threat_category = "Executive / VIP Impersonation"
        elif credential_hits:
            base_bec = 0.80
            threat_category = "Credential Harvesting Phishing"
        elif manipulation_score >= 60.0:
            base_bec = 0.65
            threat_category = "Social Engineering / Coercion"
        elif homoglyphs_count > 0:
            base_bec = 0.70
            threat_category = "Spoofed Domain / Homograph Attack"

        return base_bec, threat_category

    def _empty_response(self) -> Dict[str, Any]:
        return {
            "nlp_risk": 0.0,
            "bec_score": 0.0,
            "threat_category": "Clean / Legitimate",
            "financial_intent": False,
            "executive_impersonation": False,
            "credential_harvesting": False,
            "detected_cues": [],
            "psychological_pressure": {"urgency": 0, "fear": 0, "authority": 0, "scarcity": 0},
            "homoglyphs_detected": [],
            "zero_width_spaces_detected": 0,
            "highlighted_phrases": [],
            "transformer_nlp": {
                "predicted_category": "CLEAN_BENIGN",
                "confidence": 1.0,
                "category_probabilities": {
                    "CLEAN_BENIGN": 1.0,
                    "CREDENTIAL_HARVESTING": 0.0,
                    "FINANCIAL_WIRE_FRAUD": 0.0,
                    "INVOICE_SUPPLIER_FRAUD": 0.0,
                    "EXECUTIVE_IMPERSONATION": 0.0,
                    "EXTORTION_BLACKMAIL": 0.0
                },
                "model_name": "DeBERTa-v3-small-Quantized",
                "inference_latency_ms": 0.1
            },
            "vip_impersonation": {"is_vip_impersonation": False, "matched_vip": None}
        }
