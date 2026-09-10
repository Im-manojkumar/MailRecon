"""
MailRecon AI — Static VBA/Macro Forensics Engine
Safely parses, extracts, and triages embedded VBA macros from Office containers
(e.g., .xlsm, .docm, .doc, .xls, .pptm) without dynamic code execution.
"""

from dataclasses import dataclass, field
import io
import logging
import re
from typing import Any, Dict, List, Optional

from oletools.olevba import VBA_Parser

logger = logging.getLogger(__name__)

# Extensions that typically contain or support VBA macros
OFFICE_MACRO_EXTENSIONS = {
    ".xlsm", ".xlsb", ".xltm", ".docm", ".dotm",
    ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    ".doc", ".xls", ".ppt", ".vba"
}


@dataclass
class SuspiciousKeyword:
    type: str  # e.g., 'AutoExec', 'Suspicious', 'IOC', 'Obfuscation'
    keyword: str
    description: str


@dataclass
class MacroAnalysisResult:
    filename: str
    sha256: str
    has_macros: bool = False
    is_malicious: bool = False
    macro_count: int = 0
    triggers: List[str] = field(default_factory=list)
    suspicious_keywords: List[SuspiciousKeyword] = field(default_factory=list)
    extracted_iocs: List[Dict[str, str]] = field(default_factory=list)
    code_preview: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "has_macros": self.has_macros,
            "is_malicious": self.is_malicious,
            "macro_count": self.macro_count,
            "triggers": self.triggers,
            "suspicious_keywords": [
                {"type": k.type, "keyword": k.keyword, "description": k.description}
                for k in self.suspicious_keywords
            ],
            "extracted_iocs": self.extracted_iocs,
            "code_preview": self.code_preview,
            "error_message": self.error_message,
        }


class VbaMacroAnalyzer:
    """
    Static analyzer for Microsoft Office documents containing VBA macros.
    Analyzes raw bytes in-memory using oletools without execution.
    """

    @classmethod
    def analyze_attachment(
        cls,
        filename: str,
        raw_bytes: bytes,
        sha256: str
    ) -> MacroAnalysisResult:
        """
        Statically inspect an attachment's byte payload for VBA macros.
        """
        if not raw_bytes or len(raw_bytes) < 16:
            return MacroAnalysisResult(
                filename=filename,
                sha256=sha256,
                has_macros=False,
            )

        vba_parser: Optional[VBA_Parser] = None
        try:
            vba_parser = VBA_Parser(filename=filename, data=raw_bytes, relaxed=True)
            if not vba_parser.detect_vba_macros():
                return MacroAnalysisResult(
                    filename=filename,
                    sha256=sha256,
                    has_macros=False,
                )

            # Macros detected — extract and analyze
            extracted_code_blocks: List[str] = []
            macro_count = 0

            for subfilename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                if vba_code and vba_code.strip():
                    macro_count += 1
                    extracted_code_blocks.append(f"' --- Stream: {stream_path} ({vba_filename}) ---\n" + vba_code)

            # Analyze extracted macros using olevba analysis engine
            results = vba_parser.analyze_macros()
            
            triggers: List[str] = []
            suspicious_kws: List[SuspiciousKeyword] = []
            extracted_iocs: List[Dict[str, str]] = []
            seen_kws = set()

            for kw_type, keyword, description in results:
                kw_key = (kw_type, keyword.lower())
                if kw_key in seen_kws:
                    continue
                seen_kws.add(kw_key)

                if kw_type == "AutoExec":
                    triggers.append(keyword)
                    suspicious_kws.append(SuspiciousKeyword(type=kw_type, keyword=keyword, description=description))
                elif kw_type == "IOC":
                    extracted_iocs.append({"type": description, "value": keyword})
                else:
                    suspicious_kws.append(SuspiciousKeyword(type=kw_type, keyword=keyword, description=description))

            full_code = "\n".join(extracted_code_blocks)

            # If parser fell back to plain text, confirm it actually looks like VBA source code
            if vba_parser.type == "Text":
                has_vba_syntax = bool(re.search(r'\b(sub\s+\w+|function\s+\w+|attribute\s+vb_|dim\s+\w+)\b', full_code, re.IGNORECASE))
                if not has_vba_syntax and not triggers and not suspicious_kws:
                    return MacroAnalysisResult(
                        filename=filename,
                        sha256=sha256,
                        has_macros=False,
                    )

            # Regex search for common download URLs / IP endpoints in code if not fully caught
            url_matches = re.findall(r'https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+', full_code, re.IGNORECASE)
            for u in url_matches:
                if not any(ioc["value"] == u for ioc in extracted_iocs):
                    extracted_iocs.append({"type": "URL", "value": u})

            # Check for PowerShell or Command execution patterns
            has_execution = any(
                k.keyword.lower() in {"shell", "wscript.shell", "powershell", "cmd.exe", "createobject"}
                for k in suspicious_kws
            ) or bool(re.search(r'(powershell|cmd\.exe|wscript\.shell)', full_code, re.IGNORECASE))

            has_network = any(
                k.keyword.lower() in {"urldownloadtofile", "msxml2.xmlhttp", "winhttp.winhttprequest", "internetopen"}
                for k in suspicious_kws
            ) or bool(re.search(r'(urldownloadtofile|msxml2|winhttp)', full_code, re.IGNORECASE))

            # Weaponized heuristic: triggers + (execution or network or IOCs)
            is_malicious = bool(
                (triggers and (has_execution or has_network or extracted_iocs))
                or (has_execution and has_network)
                or (len(suspicious_kws) >= 4)
            )

            # Generate code preview (first 1200 characters of meaningful code)
            preview = full_code[:1200]
            if len(full_code) > 1200:
                preview += "\n... [truncated for forensic display] ..."

            return MacroAnalysisResult(
                filename=filename,
                sha256=sha256,
                has_macros=True,
                is_malicious=is_malicious,
                macro_count=macro_count,
                triggers=triggers,
                suspicious_keywords=suspicious_kws,
                extracted_iocs=extracted_iocs,
                code_preview=preview,
            )

        except Exception as exc:
            logger.warning(f"Error parsing VBA macros in {filename}: {exc}")
            return MacroAnalysisResult(
                filename=filename,
                sha256=sha256,
                has_macros=False,
                error_message=str(exc),
            )
        finally:
            if vba_parser:
                try:
                    vba_parser.close()
                except Exception:
                    pass
