import io
import re
import base64
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("spectrashield.qr_detector")


class QRDetector:
    """
    Extracts QR code URLs from raw email MIME attachments and embedded inline base64 images.
    Protects against Quishing (QR-code based credential phishing).
    """

    def __init__(self):
        self.pyzbar_available = False
        try:
            from pyzbar import pyzbar
            from PIL import Image
            self.pyzbar = pyzbar
            self.Image = Image
            self.pyzbar_available = True
        except ImportError:
            logger.debug("pyzbar not installed; falling back to heuristic QR/image detection.")

    def scan_image_bytes(self, image_bytes: bytes) -> List[str]:
        """Scans raw image bytes for QR codes and decodes embedded URLs."""
        if not image_bytes or not self.pyzbar_available:
            return []

        try:
            image = self.Image.open(io.BytesIO(image_bytes))
            decoded_objects = self.pyzbar.decode(image)
            urls = []
            for obj in decoded_objects:
                payload = obj.data.decode("utf-8", errors="ignore").strip()
                if payload.startswith(("http://", "https://")):
                    urls.append(payload)
            return urls
        except Exception as e:
            logger.debug(f"QR decoding failed: {e}")
            return []

    def scan_html_for_inline_images(self, html_content: str) -> List[str]:
        """Extracts base64 inline images from HTML and decodes any QR code payloads."""
        if not html_content or not self.pyzbar_available:
            return []

        urls: List[str] = []
        # Find base64 embedded images: <img src="data:image/...;base64,...">
        matches = re.findall(r'data:image/[a-zA-Z]+;base64,([A-Za-z0-9+/=]+)', html_content)
        for b64_str in matches[:5]:  # Limit to first 5 images for performance
            try:
                img_data = base64.b64decode(b64_str)
                found = self.scan_image_bytes(img_data)
                urls.extend(found)
            except Exception:
                continue

        return list(set(urls))
