import io
import re
import base64
import logging
from typing import List, Dict, Any, Optional
from PIL import Image

logger = logging.getLogger("spectrashield.qr_detector")

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tiff"}


def defang_url(url: str) -> str:
    """Defangs a URL for safe forensic display (hxxps[://]domain[.]com/path)."""
    if not url:
        return ""
    proto = ""
    rest = url
    if url.startswith("https://"):
        proto = "hxxps[://]"
        rest = url[8:]
    elif url.startswith("http://"):
        proto = "hxxp[://]"
        rest = url[7:]

    if "/" in rest:
        host, path = rest.split("/", 1)
        return f"{proto}{host.replace('.', '[.]')}/{path}"
    return f"{proto}{rest.replace('.', '[.]')}"


class QRDetector:
    """
    Extracts QR code matrices and URLs from raw email MIME attachments,
    embedded inline base64 images, and decoupled OLE/MIME image objects.
    Protects against Quishing (QR-code based credential phishing) attacks.
    """

    def __init__(self):
        self.cv2_available = False
        self.pyzbar_available = False

        # Attempt OpenCV QR detector
        try:
            import cv2
            import numpy as np
            self.cv2 = cv2
            self.np = np
            self.cv_detector = cv2.QRCodeDetector()
            self.cv2_available = True
            logger.info("OpenCV QRCodeDetector initialized for Quishing analysis.")
        except Exception as e:
            logger.debug(f"OpenCV not available for QR detection: {e}")

        # Attempt pyzbar fallback
        try:
            from pyzbar import pyzbar
            self.pyzbar = pyzbar
            self.pyzbar_available = True
            logger.info("pyzbar initialized for QR fallback.")
        except Exception as e:
            logger.debug(f"pyzbar not available: {e}")

    def scan_image_bytes(self, image_bytes: bytes) -> List[str]:
        """
        Scans raw image bytes for 2D QR matrix symbols using OpenCV and pyzbar.
        Returns all decoded string payloads.
        """
        if not image_bytes:
            return []

        urls: List[str] = []

        # 1. Try OpenCV QRCodeDetector
        if self.cv2_available:
            try:
                nparr = self.np.frombuffer(image_bytes, self.np.uint8)
                img = self.cv2.imdecode(nparr, self.cv2.IMREAD_COLOR)
                if img is not None:
                    # Single and multi-detect
                    val, pts, st = self.cv_detector.detectAndDecode(img)
                    if val and val.strip():
                        urls.append(val.strip())
                    
                    # Try detectAndDecodeMulti if available
                    if hasattr(self.cv_detector, "detectAndDecodeMulti"):
                        ok, decoded_info, points, straight_qrcode = self.cv_detector.detectAndDecodeMulti(img)
                        if ok and decoded_info:
                            for info in decoded_info:
                                if info and info.strip() and info.strip() not in urls:
                                    urls.append(info.strip())
            except Exception as e:
                logger.debug(f"OpenCV QR decode error: {e}")

        # 2. Try pyzbar if no results yet and pyzbar is available
        if not urls and self.pyzbar_available:
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                # Convert to grayscale for contrast
                gray = pil_img.convert("L")
                decoded_objects = self.pyzbar.decode(gray)
                for obj in decoded_objects:
                    payload = obj.data.decode("utf-8", errors="ignore").strip()
                    if payload and payload not in urls:
                        urls.append(payload)
            except Exception as e:
                logger.debug(f"pyzbar QR decode error: {e}")

        return urls

    def scan_html_for_inline_images(self, html_content: str) -> List[Dict[str, Any]]:
        """Extracts base64 inline images from HTML and decodes any QR code payloads."""
        if not html_content:
            return []

        results: List[Dict[str, Any]] = []
        matches = re.findall(r'data:image/([a-zA-Z]+);base64,([A-Za-z0-9+/=]+)', html_content)
        for idx, (img_type, b64_str) in enumerate(matches[:8]):
            try:
                img_data = base64.b64decode(b64_str)
                found = self.scan_image_bytes(img_data)
                for payload in found:
                    results.append({
                        "payload": payload,
                        "source": f"inline_image_{idx + 1}.{img_type}",
                        "source_type": "inline_html_base64"
                    })
            except Exception:
                continue

        return results

    def analyze_quishing(
        self,
        attachments: Optional[List[Dict[str, Any]]] = None,
        html_body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive Quishing (QR Phishing) threat analysis across both attachments
        and inline HTML images.
        """
        decoded_payloads: List[str] = []
        source_image: Optional[str] = None

        # 1. Scan image attachments
        if attachments:
            for att in attachments:
                fname = att.get("filename", "").lower()
                ctype = att.get("content_type", "").lower()
                is_image = any(fname.endswith(ext) for ext in IMAGE_EXTENSIONS) or ctype.startswith("image/")

                raw_bytes = att.get("raw_bytes") or att.get("data")
                if is_image and raw_bytes and isinstance(raw_bytes, (bytes, bytearray)):
                    found = self.scan_image_bytes(bytes(raw_bytes))
                    if found:
                        for p in found:
                            if p not in decoded_payloads:
                                decoded_payloads.append(p)
                                if not source_image:
                                    source_image = att.get("filename")

        # 2. Scan inline images in HTML body
        if html_body:
            inline_findings = self.scan_html_for_inline_images(html_body)
            for item in inline_findings:
                p = item["payload"]
                if p not in decoded_payloads:
                    decoded_payloads.append(p)
                    if not source_image:
                        source_image = item["source"]

        # 3. Categorize Quishing threat risk
        has_qr = len(decoded_payloads) > 0
        defanged_payloads = [defang_url(u) for u in decoded_payloads]

        risk_level = "clean"
        if has_qr:
            # High risk indicators: login cues, ip addresses, credential harvesting, brand lures
            is_malicious = False
            for p in decoded_payloads:
                p_lower = p.lower()
                if any(k in p_lower for k in [
                    "login", "verify", "account", "secure", "auth", "signin",
                    "bank", "escrow", "wire", "password", "wallet", "update", "billing"
                ]) or re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", p_lower):
                    is_malicious = True
                    break

            risk_level = "malicious" if is_malicious else "suspicious"

        return {
            "has_qr_code": has_qr,
            "qr_count": len(decoded_payloads),
            "decoded_payloads": decoded_payloads,
            "defanged_payloads": defanged_payloads,
            "risk_level": risk_level,
            "source_image_filename": source_image,
            "extracted_urls": [p for p in decoded_payloads if p.startswith(("http://", "https://"))]
        }


qr_detector = QRDetector()
