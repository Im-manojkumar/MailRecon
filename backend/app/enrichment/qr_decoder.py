"""
QR Code Decoder for MailRecon AI.
Inspects email attachments and inline images for embedded QR matrix codes (Quishing defense)
with strict decompression bomb and memory exhaustion protections (Threat T10).
"""
from dataclasses import asdict, dataclass
import io
import logging
from typing import Any, Dict, List, Optional

from PIL import Image

from app.config import settings
from app.parser.email_parser import AttachmentData
from app.parser.urls import defang_url

logger = logging.getLogger("mailrecon.enrichment.qr")

# Protect against decompression bombs (Threat T10)
# Cap pixel limit to 25 million pixels (~5000 x 5000)
Image.MAX_IMAGE_PIXELS = 25_000_000

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}


@dataclass
class QrCodeResult:
    attachment_name: str
    content_id: Optional[str]
    decoded_text: str
    defanged_text: str
    is_url: bool
    rect: Dict[str, int]  # {"left": x, "top": y, "width": w, "height": h}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class QrCodeDecoder:
    """
    Safely inspects email image attachments and decodes QR codes.
    """

    @classmethod
    def decode_image_bytes(
        cls, image_bytes: bytes, filename: str = "image.png", content_id: Optional[str] = None
    ) -> List[QrCodeResult]:
        if not image_bytes:
            return []

        # 1. Byte size limit check (Threat T10)
        max_bytes = getattr(settings, "MAX_IMAGE_DECODE_BYTES", 10_485_760)
        if len(image_bytes) > max_bytes:
            logger.warning(
                f"Image {filename} rejected: size {len(image_bytes)} exceeds limit of {max_bytes} bytes."
            )
            return []

        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
        except ImportError:
            logger.warning("pyzbar is not installed. QR decoding will be skipped.")
            return []

        results: List[QrCodeResult] = []

        try:
            with Image.open(io.BytesIO(image_bytes)) as img:
                # Dimension checks
                w, h = img.size
                if w * h > Image.MAX_IMAGE_PIXELS:
                    logger.warning(f"Image {filename} rejected: dimensions {w}x{h} exceed pixel limit.")
                    return []

                # Convert to RGB for pyzbar compatibility
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")

                decoded_items = pyzbar_decode(img)
                for item in decoded_items:
                    raw_text = item.data.decode("utf-8", errors="replace").strip()
                    if not raw_text:
                        continue

                    is_url = raw_text.startswith("http://") or raw_text.startswith("https://")
                    defanged = defang_url(raw_text) if is_url else raw_text

                    rect_dict = {
                        "left": getattr(item.rect, "left", 0),
                        "top": getattr(item.rect, "top", 0),
                        "width": getattr(item.rect, "width", 0),
                        "height": getattr(item.rect, "height", 0),
                    }

                    results.append(
                        QrCodeResult(
                            attachment_name=filename,
                            content_id=content_id,
                            decoded_text=raw_text,
                            defanged_text=defanged,
                            is_url=is_url,
                            rect=rect_dict,
                        )
                    )

        except Exception as e:
            logger.warning(f"Could not inspect image {filename} for QR codes: {e}")

        return results

    @classmethod
    def inspect_attachments(cls, attachments: List[AttachmentData]) -> List[QrCodeResult]:
        """Scan all image attachments and return all detected QR codes."""
        all_qr_codes: List[QrCodeResult] = []

        for att in attachments:
            content_type = (att.content_type or "").lower()
            filename_lower = (att.filename or "").lower()

            is_image = (
                content_type.startswith("image/")
                or any(filename_lower.endswith(ext) for ext in IMAGE_EXTENSIONS)
            )

            if is_image and att.raw_bytes:
                found = cls.decode_image_bytes(
                    att.raw_bytes,
                    filename=att.filename,
                    content_id=att.content_id,
                )
                all_qr_codes.extend(found)

        return all_qr_codes
