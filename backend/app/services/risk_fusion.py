from typing import Tuple, Dict, Any


def fuse_risk_scores(manipulation: float, url: float, ai_pattern: float, brand: float) -> Tuple[float, str, str]:
    """SpectraShield 1.0 Legacy Fusion Formula (Preserved for backwards compatibility)."""
    base_score = (
        manipulation * 0.30 +
        url * 0.35 +
        ai_pattern * 0.15 +
        brand * 0.20
    )

    if url >= 60:
        base_score += 15
    if manipulation >= 40:
        base_score += 15
    if brand >= 50:
        base_score += 20
    if url >= 60 and manipulation >= 15:
        base_score += 20

    final_score = min(base_score, 100.0)

    if final_score >= 75:
        verdict = "High Risk"
        confidence = "Very High Confidence"
    elif final_score >= 50:
        verdict = "High Risk"
        confidence = "High Confidence"
    elif final_score >= 35:
        verdict = "Medium Risk"
        confidence = "Moderate Confidence"
    else:
        verdict = "Low Risk"
        confidence = "Low Confidence"

    return round(final_score, 2), verdict, confidence


def fuse_forensic_scores(
    header_score: float,
    origin_score: float,
    nlp_score: float,
    url_score: float,
    killchain_severity: float = 0.0
) -> Tuple[float, str, str, Dict[str, float]]:
    """
    SpectraShield 2.0 Multi-Vector Forensic Risk Fusion Formula.
    Aggregates Header, Origin, NLP, and URL vectors (25% each) with
    dynamic escalation for severe Cyber Killchain projections.
    """
    composite = (
        (0.25 * header_score) +
        (0.25 * origin_score) +
        (0.25 * nlp_score) +
        (0.25 * url_score)
    )

    # Escalation: Tor exit nodes or failed cryptographic DMARC alignment
    if origin_score >= 70.0 and header_score >= 50.0:
        composite += 15.0

    # Escalation: BEC financial coercion combined with header mismatch
    if nlp_score >= 75.0 and header_score >= 40.0:
        composite += 20.0

    # Killchain severity override
    final_score = min(100.0, max(composite, killchain_severity))

    if final_score >= 75.0:
        verdict = "High Risk / Malicious"
        confidence = "Very High Confidence"
    elif final_score >= 50.0:
        verdict = "Suspicious / Threat Detected"
        confidence = "High Confidence"
    elif final_score >= 35.0:
        verdict = "Medium Risk / Warning"
        confidence = "Moderate Confidence"
    else:
        verdict = "Low Risk / Legitimate"
        confidence = "Verified Clean"

    breakdown = {
        "header_score": round(header_score, 2),
        "origin_score": round(origin_score, 2),
        "nlp_score": round(nlp_score, 2),
        "url_score": round(url_score, 2)
    }

    return round(final_score, 2), verdict, confidence, breakdown
