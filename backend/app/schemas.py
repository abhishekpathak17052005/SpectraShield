from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, List, Any


class SimulationStep(BaseModel):
    step: int
    title: str
    description: str


# SpectraShield 1.0 Legacy Schemas
class EmailRequest(BaseModel):
    email_text: str = ""
    email_header: Optional[str] = None
    url: Optional[str] = None
    urls: Optional[List[str]] = None
    sender_email: Optional[str] = None
    private_mode: Optional[bool] = False


class EmailResponse(BaseModel):
    final_risk: float
    verdict: str
    confidence_level: str
    breakdown: Dict[str, float]
    highlighted_phrases: Optional[List[str]] = None
    domain_age_days: Optional[int] = None
    attack_simulation: Optional[List[SimulationStep]] = None


# SpectraShield 2.0 Forensic Schemas
class ForensicAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    raw_eml: Optional[str] = None
    email_text: Optional[str] = ""
    email_header: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    private_mode: Optional[bool] = False
    thread_id: Optional[str] = None
    platform: Optional[str] = "gmail"
    sender: Optional[Any] = None
    recipient: Optional[str] = None
    body: Optional[str] = None
    urls: Optional[List[Any]] = None
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WhyFlaggedReason(BaseModel):
    category: str
    explanation: str
    evidence: str
    severity: str = "HIGH"
    contribution: Optional[float] = None


class RelayHopSchema(BaseModel):
    hop: int
    received_from: str
    by: str
    protocol: Optional[str] = "SMTP"
    ip: Optional[str] = None
    defanged_ip: Optional[str] = None
    is_private: bool
    is_origin: bool
    timestamp: Optional[str] = None
    delay_seconds: int = 0
    geo: Optional[Dict[str, Any]] = None


class OriginGeoSchema(BaseModel):
    ip: str
    defanged_ip: Optional[str] = None
    country: str
    country_code: Optional[str] = None
    city: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    is_anonymized: bool = False
    anonymization_type: Optional[str] = None
    risk_rating: float = 0.0


class CampaignSchema(BaseModel):
    id: str
    name: str
    attribution_confidence: float
    threat_actor: Optional[str] = None
    linked_incidents_count: int = 1


class QuishingEvidence(BaseModel):
    has_qr_code: bool = False
    qr_count: int = 0
    decoded_payloads: List[str] = []
    defanged_payloads: List[str] = []
    risk_level: str = "clean"  # "clean" | "suspicious" | "malicious"
    source_image_filename: Optional[str] = None
    extracted_urls: List[str] = []


class QuarantinedAttachment(BaseModel):
    filename: str
    original_extension: str
    file_size_bytes: int
    sha256: str
    md5: str
    entropy_score: float
    is_macro_enabled: bool = False
    is_executable: bool = False
    quarantine_path: str
    is_quarantined: bool = True


class AttachmentEvidence(BaseModel):
    filename: str
    content_type: str
    file_size_bytes: int
    sha256: str
    sha1: str
    md5: str
    fuzzy_hash: Optional[str] = None
    entropy_score: float = 0.0
    is_executable_or_script: bool = False
    has_macros: bool = False
    has_embedded_scripts: bool = False
    risk_level: str = "clean"
    risk_reasons: List[str] = []
    quarantine_path: Optional[str] = None
    is_quarantined: bool = False


class UpdateCaseStatusRequest(BaseModel):
    status: str
    reason: Optional[str] = ""
    actor: Optional[str] = "SOC Analyst"


class AddCaseNoteRequest(BaseModel):
    text: Optional[str] = None
    note: Optional[str] = None
    author: Optional[str] = "SOC Analyst"


class AssignCaseRequest(BaseModel):
    analyst: str
    actor: Optional[str] = "Security Admin"


class HomoglyphChar(BaseModel):
    index: int
    raw_char: str
    lookalike_char: str
    unicode_hex: str
    script: str
    char_name: Optional[str] = None


class HomoglyphAnalysis(BaseModel):
    has_homoglyphs: bool
    is_punycode: bool = False
    raw_domain: str = ""
    punycode_ascii: Optional[str] = None
    normalized_ascii: str = ""
    target_brand: Optional[str] = None
    target_domain: Optional[str] = None
    substituted_characters: List[HomoglyphChar] = []
    risk_score_modifier: float = 0.0
    verdict: str = "Clean"


class CtiReputationRecord(BaseModel):
    indicator: str
    source: str  # "Google Safe Browsing" | "URLhaus" | "AbuseIPDB" | "Commercial VPN"
    is_malicious: bool
    threat_category: Optional[str] = None
    confidence_score: float = 0.0
    details: Dict[str, Any] = {}


class DkimVerificationDetails(BaseModel):
    selector: str = ""
    signing_domain: str = ""
    key_length_bits: int = 0
    algorithm: str = "rsa-sha256"
    body_hash_valid: bool = False
    signature_math_valid: bool = False
    dns_key_published: bool = False
    raw_public_key: Optional[str] = None
    verification_status: str = "NONE"  # "PASS" | "FAIL" | "NONE"
    reason: Optional[str] = None


class TransformerNlpResult(BaseModel):
    predicted_category: str
    confidence: float
    category_probabilities: Dict[str, float]
    model_name: str = "DeBERTa-v3-small-Quantized"
    inference_latency_ms: float = 0.0


class VipRosterEntry(BaseModel):
    name: str
    title: str
    trusted_domains: List[str] = []
    is_active: bool = True


class ForensicAnalyzeResponse(BaseModel):
    case_id: str
    case_number: str
    sha256_evidence_hash: str
    sha1: str
    md5: str
    final_risk: float
    verdict: str
    threat_category: str
    reasoning_summary: str
    authentication: Dict[str, Any]
    originating_node: Dict[str, Any]
    relay_path: List[Dict[str, Any]]
    campaign: Dict[str, Any]
    nlp_intelligence: Dict[str, Any]
    attachments: List[Dict[str, Any]] = []
    breakdown: Dict[str, float]
    mitre_tactics: List[str]
    attack_simulation: Optional[List[SimulationStep]] = None
    anomalies: List[str]
    homoglyph_analysis: Optional[HomoglyphAnalysis] = None
    quishing_evidence: Optional[QuishingEvidence] = None
    ingestion_format: Optional[str] = "STANDARD_RFC5322_EML"
    sanitized_html: Optional[str] = None
    script_cues: Optional[List[str]] = None
    cti_reputation: Optional[List[Dict[str, Any]]] = None
    dkim_crypto_verification: Optional[Dict[str, Any]] = None
    dkim_verification: Optional[Dict[str, Any]] = None
    transformer_nlp: Optional[Dict[str, Any]] = None
    vip_impersonation: Optional[Dict[str, Any]] = None
    why_flagged: Optional[List[WhyFlaggedReason]] = []
    email_metadata: Optional[Dict[str, Any]] = None
    risk_factors: Optional[Dict[str, Any]] = None
    url_intelligence_list: Optional[List[Dict[str, Any]]] = None
    created_at: str



