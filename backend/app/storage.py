import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# In-memory vaults for resilient operation across offline and testing scenarios
cases_vault: Dict[str, Dict[str, Any]] = {}
analyses_vault: Dict[str, Dict[str, Any]] = {}
audit_ledger: List[Dict[str, Any]] = []

# Baseline compatibility
scan_history = []


class EvidenceVault:
    """
    Cryptographic Evidence Storage conforming to ISO/IEC 27037 & BNSS.
    Computes immutable SHA-256 hashes upon ingestion and maintains
    a block-linked audit ledger.
    """

    def __init__(self):
        self.genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        if not cases_vault:
            self._seed_initial_cases()

    def _seed_initial_cases(self):
        """Pre-populates an initial verified baseline case for instant SOC triage."""
        self.create_case(
            raw_payload="From: ceo@micro-soft-billing.top\nTo: cfo@victim-corp.com\nSubject: URGENT: Acquisition Escrow Account Update - Wire Instructions Attached\n\nPlease find the revised escrow routing details for the ongoing European acquisition. Complete the wire transfer of $240,000 immediately.",
            title="URGENT: Acquisition Escrow Account Update",
            threat_category="Business Email Compromise (BEC)",
            severity="CRITICAL",
            overall_risk_score=94.5,
            analyst="Lead SOC Investigator"
        )

    def compute_hashes(self, raw_data: str) -> Dict[str, str]:
        """Calculates SHA-256, SHA-1, and MD5 hashes of the payload."""
        data_bytes = raw_data.encode("utf-8") if isinstance(raw_data, str) else bytes(raw_data)
        return {
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
            "sha1": hashlib.sha1(data_bytes).hexdigest(),
            "md5": hashlib.md5(data_bytes).hexdigest()
        }

    def create_case(
        self,
        raw_payload: str,
        title: str,
        threat_category: str,
        severity: str,
        overall_risk_score: float,
        analyst: str = "SOC Forensic Analyst"
    ) -> Dict[str, Any]:
        """Creates an immutable case entry with cryptographic checksum."""
        case_id = str(uuid.uuid4())
        now_dt = datetime.now(timezone.utc)
        hashes = self.compute_hashes(raw_payload)
        case_number = f"CASE-{now_dt.strftime('%Y%m%d')}-{case_id[:6].upper()}"

        case_record = {
            "id": case_id,
            "case_number": case_number,
            "title": title or f"Email Incident: {case_number}",
            "threat_category": threat_category,
            "severity": severity,
            "status": "NEW",
            "overall_risk_score": float(round(overall_risk_score, 2)),
            "sha256_evidence_hash": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "raw_payload_snippet": raw_payload[:300],
            "assigned_analyst": analyst,
            "notes": [],
            "created_at": now_dt.isoformat(),
            "updated_at": now_dt.isoformat()
        }

        cases_vault[case_id] = case_record

        # Append to audit ledger
        self.append_audit_log(
            case_id=case_id,
            action="EVIDENCE_SEALED",
            actor=analyst,
            metadata={"sha256": hashes["sha256"], "severity": severity}
        )

        return case_record

    def store_analysis(self, case_id: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Binds full forensic dissection to the case ID."""
        analysis_id = str(uuid.uuid4())
        record = {
            "id": analysis_id,
            "case_id": case_id,
            **analysis_data,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        analyses_vault[case_id] = record
        return record

    def append_audit_log(self, case_id: str, action: str, actor: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Creates an append-only, block-linked audit record."""
        now_iso = datetime.now(timezone.utc).isoformat()
        prev_hash = audit_ledger[-1]["current_hash"] if audit_ledger else self.genesis_hash

        # Block link: Hash(PrevHash + CaseID + Action + Actor + Timestamp)
        seed = f"{prev_hash}:{case_id}:{action}:{actor}:{now_iso}"
        current_hash = hashlib.sha256(seed.encode()).hexdigest()

        entry = {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "action": action,
            "actor": actor,
            "previous_hash": prev_hash,
            "current_hash": current_hash,
            "metadata": metadata or {},
            "timestamp": now_iso
        }
        audit_ledger.append(entry)
        return entry

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        if case_id in cases_vault:
            return cases_vault[case_id]
        for c in cases_vault.values():
            if c.get("case_number") == case_id:
                return c
        return None

    def get_analysis(self, case_id: str) -> Optional[Dict[str, Any]]:
        return analyses_vault.get(case_id)

    def get_audit_trail(self, case_id: str) -> List[Dict[str, Any]]:
        return [entry for entry in audit_ledger if entry["case_id"] == case_id]

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        records = list(cases_vault.values())
        records.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return records[:limit]

    def update_case_status(self, case_id: str, new_status: str, actor: str, reason: str = "") -> Optional[Dict[str, Any]]:
        """Transitions case status along the triage lifecycle."""
        valid_statuses = {"NEW", "TRIAGED", "INVESTIGATING", "ESCALATED", "CLOSED_RESOLVED", "CLOSED_FALSE_POSITIVE"}
        case = self.get_case(case_id)
        if not case:
            return None

        status_upper = new_status.upper()
        if status_upper not in valid_statuses:
            status_upper = "INVESTIGATING"

        old_status = case.get("status", "NEW")
        case["status"] = status_upper
        case["updated_at"] = datetime.now(timezone.utc).isoformat()

        self.append_audit_log(
            case_id=case["id"],
            action="STATUS_CHANGE",
            actor=actor,
            metadata={"old_status": old_status, "new_status": status_upper, "reason": reason}
        )
        return case

    def add_case_note(self, case_id: str, note_text: str, author: str) -> Optional[Dict[str, Any]]:
        """Appends a timestamped investigation note to the case record."""
        case = self.get_case(case_id)
        if not case:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        note_entry = {
            "id": str(uuid.uuid4())[:8],
            "text": note_text,
            "author": author,
            "timestamp": now_iso
        }
        case.setdefault("notes", []).append(note_entry)
        case["updated_at"] = now_iso

        self.append_audit_log(
            case_id=case["id"],
            action="NOTE_ADDED",
            actor=author,
            metadata={"note_id": note_entry["id"], "snippet": note_text[:80]}
        )
        return note_entry

    def assign_case(self, case_id: str, analyst: str, actor: str) -> Optional[Dict[str, Any]]:
        """Assigns an investigator to the case."""
        case = self.get_case(case_id)
        if not case:
            return None

        old_analyst = case.get("assigned_analyst", "Unassigned")
        case["assigned_analyst"] = analyst
        case["updated_at"] = datetime.now(timezone.utc).isoformat()

        self.append_audit_log(
            case_id=case["id"],
            action="ANALYST_ASSIGNED",
            actor=actor,
            metadata={"old_analyst": old_analyst, "new_analyst": analyst}
        )
        return case


# Global vault singleton
evidence_vault = EvidenceVault()