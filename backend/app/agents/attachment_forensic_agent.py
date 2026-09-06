import re
import math
import hashlib
import io
import os
import zipfile
from email import message_from_string, message_from_bytes
from typing import List, Dict, Any, Optional


def compute_shannon_entropy(data: bytes) -> float:
    """Computes the Shannon entropy of a byte stream (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    data_len = len(data)
    for count in freq.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def compute_fuzzy_simhash(data: bytes) -> str:
    """
    Computes a 64-bit rolling simhash fingerprint in pure Python
    providing cross-platform fuzzy similarity matching without requiring C libraries.
    """
    if not data:
        return "0000000000000000"
    v = [0] * 64
    chunk_size = max(4, min(32, len(data) // 16))
    for i in range(0, len(data) - chunk_size + 1, max(1, chunk_size // 2)):
        chunk = data[i:i + chunk_size]
        h = int(hashlib.md5(chunk).hexdigest()[:16], 16)
        for bit in range(64):
            if (h >> bit) & 1:
                v[bit] += 1
            else:
                v[bit] -= 1
    simhash = 0
    for bit in range(64):
        if v[bit] > 0:
            simhash |= (1 << bit)
    return f"{simhash:016x}"


class AttachmentForensicAgent:
    """
    Decompiles email MIME attachments and executes safe, static forensic analysis:
    - Multi-hash fingerprinting (SHA-256, SHA-1, MD5, Fuzzy SimHash)
    - PDF exploit stream detection (/JavaScript, /JS, /Launch, /EmbeddedFiles)
    - Office VBA macro detection (vbaProject.bin in OOXML and OLE structures)
    - Deceptive double-extension and script lure flagging
    - Shannon entropy calculation for packed/encrypted payloads
    """

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".vbs", ".bat", ".scr", ".cmd", ".iso", ".img",
        ".pif", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta",
        ".cpl", ".dll", ".jar"
    }

    DOUBLE_EXTENSION_PATTERN = re.compile(
        r"\.(pdf|docx|xlsx|pptx|txt|jpg|png|csv)\.(exe|vbs|bat|scr|cmd|iso|img|pif|js|hta|ps1)$",
        re.IGNORECASE
    )

    PDF_SUSPICIOUS_TOKENS = [
        (b"/JavaScript", "PDF contains embedded JavaScript stream"),
        (b"/JS", "PDF contains abbreviated JavaScript action"),
        (b"/Launch", "PDF attempts to launch an external OS process"),
        (b"/EmbeddedFiles", "PDF carries hidden embedded file payloads"),
        (b"/OpenAction", "PDF auto-executes actions immediately upon opening"),
    ]

    def quarantine_attachment(self, data: bytes, case_id: str, sha256: str) -> str:
        """
        Isolates attachment bytes in a non-executable disk quarantine vault:
        backend/data/quarantine/{case_id}/{sha256}.quarantine
        """
        try:
            import stat
            base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "quarantine", case_id)
            os.makedirs(base_dir, exist_ok=True)
            quarantine_file = os.path.join(base_dir, f"{sha256}.quarantine")

            if os.path.exists(quarantine_file):
                return f"data/quarantine/{case_id}/{sha256}.quarantine"

            with open(quarantine_file, "wb") as f:
                f.write(data)

            # Restrict permissions to read-only
            try:
                os.chmod(quarantine_file, stat.S_IREAD)
            except Exception:
                pass

            return f"data/quarantine/{case_id}/{sha256}.quarantine"
        except Exception as e:
            return f"quarantine_err: {e}"


    def analyze_attachments_from_mime(self, raw_eml: str, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extracts and statically inspects attachments from an RFC 5322 MIME string."""
        if not raw_eml:
            return []

        try:
            msg = message_from_string(raw_eml)
        except Exception:
            return []

        attachments = []
        for part in msg.walk():
            # Check for attachments
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if not filename and "attachment" not in content_disposition.lower():
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            if not filename:
                filename = f"unnamed_attachment_{len(attachments) + 1}.bin"

            content_type = part.get_content_type() or "application/octet-stream"
            evidence = self.inspect_attachment_bytes(filename, content_type, payload, case_id=case_id)
            attachments.append(evidence)

        return attachments

    def inspect_attachment_bytes(self, filename: str, content_type: str, data: bytes, case_id: Optional[str] = None) -> Dict[str, Any]:
        """Performs static forensic inspection on an extracted attachment byte stream."""
        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        fuzzy_hash = compute_fuzzy_simhash(data)
        entropy = compute_shannon_entropy(data)

        risk_reasons = []
        is_executable = False
        has_macros = False
        has_embedded_scripts = False

        # 1. Extension inspection
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        if ext in self.EXECUTABLE_EXTENSIONS:
            is_executable = True
            risk_reasons.append(f"Dangerous executable/script attachment extension ({ext})")

        if self.DOUBLE_EXTENSION_PATTERN.search(filename):
            risk_reasons.append(f"Deceptive double-extension disguise detected ({filename})")

        # 2. PDF static stream inspection
        if ext == ".pdf" or data.startswith(b"%PDF-"):
            for token, explanation in self.PDF_SUSPICIOUS_TOKENS:
                if token in data:
                    has_embedded_scripts = True
                    risk_reasons.append(explanation)

        # 3. Office macro stream inspection
        if ext in {".docx", ".docm", ".dotm", ".xlsm", ".xltm", ".pptm"} or ext in {".doc", ".xls", ".ppt"}:
            # Check for OOXML containing vbaProject.bin
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    for name in zf.namelist():
                        if "vbaProject.bin" in name or "word/vba" in name or "xl/vba" in name:
                            has_macros = True
                            risk_reasons.append("Office document contains compiled VBA macro project (vbaProject.bin)")
                            break
            except Exception:
                pass

            # Check for OLE binary header with WordDocument / VBA streams
            if b"Attribut" in data and b"VB_Name" in data:
                has_macros = True
                risk_reasons.append("Legacy OLE Office binary contains active VBA project streams")

        # 4. Entropy analysis
        if entropy > 7.4 and ext not in {".zip", ".gz", ".7z", ".png", ".jpg", ".jpeg"}:
            risk_reasons.append(f"High Shannon entropy ({entropy}/8.0) indicates packed, encrypted, or obfuscated payload")

        # 5. Determine risk level
        if is_executable or has_macros or has_embedded_scripts or any("double-extension" in r for r in risk_reasons):
            risk_level = "malicious"
        elif len(risk_reasons) > 0 or entropy > 7.1:
            risk_level = "suspicious"
        else:
            risk_level = "clean"

        # 6. Disk Quarantine Isolation
        quarantine_path = None
        is_quarantined = False
        if case_id:
            quarantine_path = self.quarantine_attachment(data, case_id, sha256)
            is_quarantined = True

        return {
            "filename": filename,
            "content_type": content_type,
            "file_size_bytes": file_size,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "fuzzy_hash": fuzzy_hash,
            "entropy_score": entropy,
            "is_executable_or_script": is_executable,
            "has_macros": has_macros,
            "has_embedded_scripts": has_embedded_scripts,
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
            "quarantine_path": quarantine_path,
            "is_quarantined": is_quarantined,
            "raw_bytes": data,
        }


attachment_forensic_agent = AttachmentForensicAgent()

