from pydantic import BaseModel
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
    class Config:
        extra = "allow"

    raw_eml: Optional[str] = None
    email_text: Optional[str] = ""
    email_header: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    private_mode: Optional[bool] = False
    thread_id: Optional[str] = None


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


class UpdateCaseStatusRequest(BaseModel):
    status: str
    reason: Optional[str] = ""
    actor: Optional[str] = "SOC Analyst"


class AddCaseNoteRequest(BaseModel):
    text: str
    author: Optional[str] = "SOC Analyst"


class AssignCaseRequest(BaseModel):
    analyst: str
    actor: Optional[str] = "Security Admin"


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
    created_at: str
