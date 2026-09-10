from dataclasses import dataclass, field
import email
from email import policy
from email.message import EmailMessage
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from app.config import settings
from app.parser.auth_headers import parse_authentication_results
from app.parser.received import parse_received_headers
from app.parser.sanitizer import sanitize_html
from app.parser.urls import extract_urls

MACRO_EXTENSIONS = {
    ".xlsm", ".xlsb", ".xltm", ".docm", ".dotm",
    ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".exe", ".bat", ".cmd", ".ps1", ".scr", ".pif"
}


@dataclass
class AttachmentData:
    filename: str
    content_type: str
    size: int
    sha256: str
    is_macro: bool
    is_inline: bool
    content_id: Optional[str]
    storage_key: Optional[str] = None
    raw_bytes: bytes = b""


@dataclass
class ParsedEmailResult:
    headers: Dict[str, Any]
    body_text: str
    body_html: str
    raw_html: str
    blocked_images: List[str]
    attachments: List[AttachmentData]
    urls: List[Dict[str, Any]]
    auth_results: Dict[str, Any]
    received_chain: List[Dict[str, Any]]
    mime_depth_exceeded: bool = False


class EmailParser:
    @staticmethod
    def _decode_part_payload(part: EmailMessage) -> str:
        """Decode a text payload handling various charsets and malformed encodings."""
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
            elif isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
        except Exception:
            pass

        # Fallback to get_payload
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                return payload.decode("latin-1", errors="replace")
        elif isinstance(payload, str):
            return payload
        return ""

    @classmethod
    def parse(cls, raw_eml_bytes: bytes) -> ParsedEmailResult:
        """
        Parse raw .eml bytes into structured, normalized, and sanitized forensic structures.
        Enforces MAX_MIME_DEPTH to defend against nested MIME bombs.
        """
        msg = email.message_from_bytes(raw_eml_bytes, policy=policy.default)

        # 1. Normalize Headers
        headers_dict: Dict[str, Any] = {}
        for key in msg.keys():
            normalized_key = key.lower()
            values = msg.get_all(key, [])
            # For headers with single value, keep single; for Received, keep list
            if normalized_key == "received":
                headers_dict[normalized_key] = [str(v) for v in values]
            elif len(values) == 1:
                headers_dict[normalized_key] = str(values[0])
            else:
                headers_dict[normalized_key] = [str(v) for v in values]

        # Convenience accessors for common headers
        headers_summary = {
            "subject": str(msg.get("subject", "")),
            "from": str(msg.get("from", "")),
            "to": str(msg.get("to", "")),
            "cc": str(msg.get("cc", "")),
            "reply_to": str(msg.get("reply-to", "")),
            "date": str(msg.get("date", "")),
            "message_id": str(msg.get("message-id", "")),
            "return_path": str(msg.get("return-path", "")),
            "all_headers": headers_dict,
        }

        # 2. Walk MIME Structure with recursion depth limit
        text_bodies: List[str] = []
        html_bodies: List[str] = []
        attachments: List[AttachmentData] = []
        depth_exceeded = False

        def walk_parts(part: EmailMessage, current_depth: int):
            nonlocal depth_exceeded
            if current_depth > settings.MAX_MIME_DEPTH:
                depth_exceeded = True
                return

            # Check if this part is an attachment or inline file
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_id = part.get("Content-ID", "").strip("<>")

            is_attachment = disposition == "attachment" or (filename is not None and disposition != "inline")
            is_inline_asset = disposition == "inline" and (filename is not None or content_id)

            if (is_attachment or is_inline_asset) and not part.is_multipart():
                payload = part.get_payload(decode=True) or b""
                att_sha256 = hashlib.sha256(payload).hexdigest()
                safe_filename = filename or f"unnamed_{att_sha256[:8]}"
                ext = Path(safe_filename).suffix.lower()
                is_macro = ext in MACRO_EXTENSIONS

                attachments.append(AttachmentData(
                    filename=safe_filename,
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=att_sha256,
                    is_macro=is_macro,
                    is_inline=bool(is_inline_asset and not is_attachment),
                    content_id=content_id or None,
                    raw_bytes=payload,
                ))
                return

            if part.is_multipart():
                for subpart in part.iter_parts():
                    walk_parts(subpart, current_depth + 1)
            else:
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    text_bodies.append(cls._decode_part_payload(part))
                elif ctype == "text/html":
                    html_bodies.append(cls._decode_part_payload(part))

        walk_parts(msg, current_depth=1)

        full_text_body = "\n\n".join(text_bodies).strip()
        raw_html_body = "\n\n".join(html_bodies).strip()

        # 3. Sanitize HTML
        sanitized_html, blocked_images = sanitize_html(raw_html_body)

        # 4. Extract URLs
        extracted_urls = extract_urls(full_text_body, raw_html_body)

        # 5. Parse Authentication-Results & Received-SPF
        auth_headers_list = msg.get_all("Authentication-Results", [])
        rspf_headers_list = msg.get_all("Received-SPF", [])
        auth_results = parse_authentication_results(
            [str(h) for h in auth_headers_list],
            [str(h) for h in rspf_headers_list],
        )

        # 6. Parse Received Hop Chain
        received_list = msg.get_all("Received", [])
        received_chain = parse_received_headers([str(h) for h in received_list])

        return ParsedEmailResult(
            headers=headers_summary,
            body_text=full_text_body,
            body_html=sanitized_html,
            raw_html=raw_html_body,
            blocked_images=blocked_images,
            attachments=attachments,
            urls=extracted_urls,
            auth_results=auth_results,
            received_chain=received_chain,
            mime_depth_exceeded=depth_exceeded,
        )
