import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

try:
    from app.database import (
        forensic_cases_collection,
        forensic_analyses_collection,
        audit_ledger_collection,
        users_collection
    )
except Exception:
    forensic_cases_collection = None
    forensic_analyses_collection = None
    audit_ledger_collection = None
    users_collection = None

# In-memory vaults for resilient operation across offline and testing scenarios
cases_vault: Dict[str, Dict[str, Any]] = {}
analyses_vault: Dict[str, Dict[str, Any]] = {}
audit_ledger: List[Dict[str, Any]] = []
users_vault: Dict[str, Dict[str, Any]] = {}

# Baseline compatibility
scan_history = []


class EvidenceVault:
    """
    Cryptographic Evidence Storage conforming to ISO/IEC 27037 & BNSS.
    Computes immutable SHA-256 hashes upon ingestion, persists records
    to Supabase / PostgreSQL collections, and maintains a block-linked audit ledger.
    """

    def __init__(self):
        self.genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self._load_existing_db_cases()
        if not cases_vault:
            self._seed_initial_cases()

    def _load_existing_db_cases(self):
        """Loads existing cases, analyses, and audit logs from DB into memory cache."""
        if forensic_cases_collection is not None:
            try:
                cursor = forensic_cases_collection.find({})
                count = 0
                for doc in cursor:
                    cid = doc.get("id")
                    cnum = doc.get("case_number")
                    if cid:
                        cases_vault[cid] = doc
                        count += 1
                    if cnum:
                        cases_vault[cnum] = doc
                if count > 0 and audit_ledger_collection is not None:
                    try:
                        for entry in audit_ledger_collection.find({}):
                            if entry not in audit_ledger:
                                audit_ledger.append(entry)
                    except Exception:
                        pass
            except Exception:
                pass

        if forensic_analyses_collection is not None:
            try:
                cursor = forensic_analyses_collection.find({})
                for doc in cursor:
                    doc.pop("_id", None)
                    aid = doc.get("id")
                    cid = doc.get("case_id")
                    cnum = doc.get("case_number")
                    if aid:
                        analyses_vault[aid] = doc
                    if cid:
                        analyses_vault[cid] = doc
                    if cnum:
                        analyses_vault[cnum] = doc
            except Exception:
                pass

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

        if isinstance(raw_payload, bytes):
            snippet = raw_payload[:300].decode("utf-8", errors="replace")
        else:
            snippet = str(raw_payload)[:300]

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
            "raw_payload_snippet": snippet,
            "assigned_analyst": analyst,
            "notes": [],
            "created_at": now_dt.isoformat(),
            "updated_at": now_dt.isoformat()
        }

        cases_vault[case_id] = case_record

        # Persist to DB if available
        if forensic_cases_collection is not None:
            try:
                forensic_cases_collection.update_one(
                    {"id": case_id},
                    {"$set": dict(case_record)},
                    upsert=True
                )
            except Exception:
                pass

        # Append to audit ledger
        self.append_audit_log(
            case_id=case_id,
            action="EVIDENCE_SEALED",
            actor=analyst,
            metadata={"sha256": hashes["sha256"], "severity": severity}
        )

        return case_record

    def store_analysis(self, case_id: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Binds full forensic dissection to the case ID and case number."""
        analysis_id = str(uuid.uuid4())
        record = {
            "id": analysis_id,
            "case_id": case_id,
            **analysis_data,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        analyses_vault[case_id] = record
        cnum = analysis_data.get("case_number")
        if cnum:
            analyses_vault[cnum] = record

        # Persist to DB if available
        if forensic_analyses_collection is not None:
            try:
                forensic_analyses_collection.update_one(
                    {"case_id": case_id},
                    {"$set": dict(record)},
                    upsert=True
                )
            except Exception:
                pass

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

        # Persist to DB if available
        if audit_ledger_collection is not None:
            try:
                audit_ledger_collection.insert_one(dict(entry))
            except Exception:
                pass

        return entry

    record_audit = append_audit_log

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        if case_id in cases_vault:
            return cases_vault[case_id]
        for c in cases_vault.values():
            if c.get("case_number") == case_id:
                return c

        if forensic_cases_collection is not None:
            try:
                doc = forensic_cases_collection.find_one({"id": case_id})
                if not doc:
                    doc = forensic_cases_collection.find_one({"case_number": case_id})
                if doc:
                    doc.pop("_id", None)
                    cases_vault[doc.get("id", case_id)] = doc
                    if doc.get("case_number"):
                        cases_vault[doc["case_number"]] = doc
                    return doc
            except Exception:
                pass

        return None

    def get_analysis(self, case_id: str) -> Optional[Dict[str, Any]]:
        # 1. Direct hit in memory
        if case_id in analyses_vault:
            return analyses_vault[case_id]

        # 2. Iterate memory vault by case_number, case_id, or id
        for a in analyses_vault.values():
            if a.get("case_number") == case_id or a.get("case_id") == case_id or a.get("id") == case_id:
                return a

        # 3. Resolve parent case to get alternate ID
        case = self.get_case(case_id)
        if case:
            real_id = case.get("id")
            cnum = case.get("case_number")
            if real_id and real_id in analyses_vault:
                return analyses_vault[real_id]
            if cnum and cnum in analyses_vault:
                return analyses_vault[cnum]

        # 4. Search DB collection by case_id, case_number, or parent case ID
        if forensic_analyses_collection is not None:
            try:
                doc = forensic_analyses_collection.find_one({"case_id": case_id})
                if not doc:
                    doc = forensic_analyses_collection.find_one({"case_number": case_id})
                if not doc and case and case.get("id"):
                    doc = forensic_analyses_collection.find_one({"case_id": case["id"]})
                if doc:
                    doc.pop("_id", None)
                    analyses_vault[case_id] = doc
                    if doc.get("case_number"):
                        analyses_vault[doc["case_number"]] = doc
                    if doc.get("case_id"):
                        analyses_vault[doc["case_id"]] = doc
                    return doc
            except Exception:
                pass

        return None

    def get_audit_trail(self, case_id: str) -> List[Dict[str, Any]]:
        case = self.get_case(case_id)
        target_ids = {case_id}
        if case:
            if case.get("id"):
                target_ids.add(case["id"])
            if case.get("case_number"):
                target_ids.add(case["case_number"])

        entries = [entry for entry in audit_ledger if entry.get("case_id") in target_ids]
        if not entries and audit_ledger_collection is not None:
            try:
                for tid in list(target_ids):
                    db_entries = list(audit_ledger_collection.find({"case_id": tid}))
                    if db_entries:
                        for e in db_entries:
                            e.pop("_id", None)
                            if e not in entries:
                                entries.append(e)
            except Exception:
                pass
        return entries

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        db_records = []
        if forensic_cases_collection is not None:
            try:
                cursor = forensic_cases_collection.find({})
                for r in cursor:
                    r.pop("_id", None)
                    if isinstance(r.get("raw_payload_snippet"), bytes):
                        r["raw_payload_snippet"] = r["raw_payload_snippet"].decode("utf-8", errors="replace")
                    if r.get("id"):
                        cases_vault[r["id"]] = r
                        db_records.append(r)
            except Exception:
                pass

        records = db_records if db_records else list(cases_vault.values())
        for r in records:
            if isinstance(r.get("raw_payload_snippet"), bytes):
                r["raw_payload_snippet"] = r["raw_payload_snippet"].decode("utf-8", errors="replace")

        records.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return records[:limit]

    def update_case_status(self, case_id: str, new_status: str, actor: str = "SOC Analyst", reason: str = "") -> Optional[Dict[str, Any]]:
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

        if forensic_cases_collection is not None:
            try:
                forensic_cases_collection.update_one(
                    {"id": case["id"]},
                    {"$set": {"status": status_upper, "updated_at": case["updated_at"]}}
                )
            except Exception:
                pass

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

        if forensic_cases_collection is not None:
            try:
                forensic_cases_collection.update_one(
                    {"id": case["id"]},
                    {"$set": {"notes": case["notes"], "updated_at": now_iso}}
                )
            except Exception:
                pass

        snippet_text = (note_text or "")[:80]
        self.append_audit_log(
            case_id=case["id"],
            action="NOTE_ADDED",
            actor=author,
            metadata={"note_id": note_entry["id"], "snippet": snippet_text}
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

        if forensic_cases_collection is not None:
            try:
                forensic_cases_collection.update_one(
                    {"id": case["id"]},
                    {"$set": {"assigned_analyst": analyst, "updated_at": case["updated_at"]}}
                )
            except Exception:
                pass

        self.append_audit_log(
            case_id=case["id"],
            action="ANALYST_ASSIGNED",
            actor=actor,
            metadata={"old_analyst": old_analyst, "new_analyst": analyst}
        )
        return case


# Global vault singleton
evidence_vault = EvidenceVault()


class UserStore:
    """
    Enterprise Identity and Credential Store supporting 4-tier RBAC,
    Bcrypt password hashes, and RFC 6238 TOTP secrets.
    """

    def __init__(self):
        self._load_existing_db_users()
        if not users_vault:
            self._seed_default_users()

    def _load_existing_db_users(self):
        """Populates in-memory vault from DB if records exist."""
        if users_collection is not None:
            try:
                cursor = users_collection.find({})
                for doc in cursor:
                    doc.pop("_id", None)
                    uid = doc.get("id")
                    if uid:
                        users_vault[uid] = doc
            except Exception:
                pass

    def _seed_default_users(self):
        """Seeds default accounts across the 4 enterprise roles."""
        from app.security import (
            hash_password,
            generate_totp_secret,
            ROLE_SUPER_ADMIN,
            ROLE_FORENSIC_ANALYST,
            ROLE_SOC_OPERATOR,
            ROLE_AUDITOR,
        )

        seeds = [
            {
                "id": "usr-super-admin-01",
                "email": "admin@spectrashield.soc",
                "name": "Chief InfoSec Officer",
                "role": ROLE_SUPER_ADMIN,
                "password": "Admin@Spectra2026!",
                "totp_enabled": False,
            },
            {
                "id": "usr-forensic-analyst-01",
                "email": "analyst@spectrashield.soc",
                "name": "Lead Forensic Investigator",
                "role": ROLE_FORENSIC_ANALYST,
                "password": "Analyst@Spectra2026!",
                "totp_enabled": False,
            },
            {
                "id": "usr-soc-operator-01",
                "email": "operator@spectrashield.soc",
                "name": "SOC Tier-1 Operator",
                "role": ROLE_SOC_OPERATOR,
                "password": "Operator@Spectra2026!",
                "totp_enabled": False,
            },
            {
                "id": "usr-auditor-01",
                "email": "auditor@spectrashield.soc",
                "name": "Compliance Auditor",
                "role": ROLE_AUDITOR,
                "password": "Auditor@Spectra2026!",
                "totp_enabled": False,
            },
        ]

        now_iso = datetime.now(timezone.utc).isoformat()
        for u in seeds:
            user_doc = {
                "id": u["id"],
                "email": u["email"].lower(),
                "name": u["name"],
                "role": u["role"],
                "hashed_password": hash_password(u["password"]),
                "totp_secret": generate_totp_secret(),
                "totp_enabled": u["totp_enabled"],
                "created_at": now_iso,
                "updated_at": now_iso,
                "last_login": None,
            }
            users_vault[u["id"]] = user_doc
            if users_collection is not None:
                try:
                    users_collection.update_one(
                        {"id": u["id"]},
                        {"$set": user_doc},
                        upsert=True
                    )
                except Exception:
                    pass

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Finds user by unique ID."""
        if user_id in users_vault:
            return users_vault[user_id]
        if users_collection is not None:
            try:
                doc = users_collection.find_one({"id": user_id})
                if doc:
                    doc.pop("_id", None)
                    users_vault[user_id] = doc
                    return doc
            except Exception:
                pass
        return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Finds user by case-insensitive email."""
        clean_email = email.strip().lower()
        for u in users_vault.values():
            if u.get("email", "").lower() == clean_email:
                return u
        if users_collection is not None:
            try:
                doc = users_collection.find_one({"email": clean_email})
                if doc:
                    doc.pop("_id", None)
                    if doc.get("id"):
                        users_vault[doc["id"]] = doc
                    return doc
            except Exception:
                pass
        return None

    def update_user(self, user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Applies field updates to a user record."""
        user = self.get_user_by_id(user_id)
        if not user:
            return None
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        user.update(updates)
        if users_collection is not None:
            try:
                users_collection.update_one({"id": user_id}, {"$set": updates})
            except Exception:
                pass
        return user

    def update_user_totp(self, user_id: str, secret: str, enabled: bool) -> Optional[Dict[str, Any]]:
        """Updates TOTP secret and enablement flag."""
        return self.update_user(user_id, {
            "totp_secret": secret,
            "totp_enabled": enabled
        })

    def record_login(self, user_id: str):
        """Records the login timestamp for an authenticated session."""
        now_iso = datetime.now(timezone.utc).isoformat()
        self.update_user(user_id, {"last_login": now_iso})

    def list_users(self) -> List[Dict[str, Any]]:
        """Returns safe user profiles stripped of sensitive hash and TOTP secrets."""
        user_list = []
        for u in users_vault.values():
            safe_user = dict(u)
            safe_user.pop("hashed_password", None)
            safe_user.pop("totp_secret", None)
            user_list.append(safe_user)
        return user_list


user_store = UserStore()
