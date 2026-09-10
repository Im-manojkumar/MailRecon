import os
from pathlib import Path
import re
from typing import List

from app.detectors.base import BaseDetector, FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1",
    ".pif", ".cpl", ".msc", ".jar", ".com"
}

ARCHIVE_CONTAINER_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".vhdx", ".rar", ".7z", ".tar.gz"
}


class SuspiciousAttachmentDetector(BaseDetector):
    name = "suspicious_attachment"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []

        for idx, att in enumerate(parsed.attachments):
            ext = Path(att.filename).suffix.lower()
            ev_ref = f"attachments[{idx}].{att.filename}"

            # 1. Double extension check (e.g. invoice.pdf.exe)
            name_parts = att.filename.lower().rsplit(".", 2)
            if len(name_parts) >= 3:
                inner_ext = f".{name_parts[1]}"
                outer_ext = f".{name_parts[2]}"
                if inner_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".txt"] and outer_ext in EXECUTABLE_EXTENSIONS:
                    findings.append(FindingData(
                        detector=self.name,
                        severity=SeverityLevel.critical,
                        title=f"Deceptive Double Extension File Masking ({att.filename})",
                        detail=(
                            f"The attachment '{att.filename}' employs double extension obfuscation "
                            f"to disguise an executable format ('{outer_ext}') as a harmless file ('{inner_ext}')."
                        ),
                        evidence_ref=ev_ref,
                        confidence=0.98,
                        raw_evidence={
                            "filename": att.filename,
                            "sha256": att.sha256,
                            "content_type": att.content_type,
                            "size": att.size,
                        }
                    ))
                    continue

            # 2. Executable / Script Format
            if ext in EXECUTABLE_EXTENSIONS:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.critical,
                    title=f"Dangerous Executable/Script Attachment ({att.filename})",
                    detail=(
                        f"The attachment '{att.filename}' has a dangerous executable or scripting extension ('{ext}'). "
                        "Direct delivery of active code via email represents an imminent compromise vector."
                    ),
                    evidence_ref=ev_ref,
                    confidence=0.98,
                    raw_evidence={
                        "filename": att.filename,
                        "sha256": att.sha256,
                        "content_type": att.content_type,
                        "size": att.size,
                    }
                ))
                continue

            # 3. Macro-Enabled Document
            if att.is_macro:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title=f"Macro-Enabled Office Attachment ({att.filename})",
                    detail=(
                        f"The attachment '{att.filename}' is a macro-enabled Office container. "
                        "Adversaries frequently weaponize VBA macros to download second-stage malware or ransomware."
                    ),
                    evidence_ref=ev_ref,
                    confidence=0.95,
                    raw_evidence={
                        "filename": att.filename,
                        "sha256": att.sha256,
                        "content_type": att.content_type,
                        "size": att.size,
                        "is_macro": True,
                    }
                ))
                continue

            # 4. Disk Image / Suspicious Container
            if ext in ARCHIVE_CONTAINER_EXTENSIONS:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.medium,
                    title=f"Container / Disk Image Attachment ({att.filename})",
                    detail=(
                        f"The attachment '{att.filename}' is a disk image or uncommon container format ('{ext}'). "
                        "Disk images are commonly used to bypass Mark-of-the-Web (MOTW) security controls."
                    ),
                    evidence_ref=ev_ref,
                    confidence=0.85,
                    raw_evidence={
                        "filename": att.filename,
                        "sha256": att.sha256,
                        "content_type": att.content_type,
                        "size": att.size,
                    }
                ))

        return findings
