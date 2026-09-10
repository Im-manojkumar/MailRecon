from unittest.mock import MagicMock, patch
import pytest

from app.detectors.base import FindingData
from app.detectors.suspicious_attachment import SuspiciousAttachmentDetector
from app.forensics.macro_analyzer import MacroAnalysisResult, SuspiciousKeyword, VbaMacroAnalyzer
from app.models.finding import SeverityLevel
from app.parser.email_parser import AttachmentData, ParsedEmailResult


def test_vba_macro_analyzer_clean_file():
    """Verify clean attachments return has_macros=False without error."""
    clean_bytes = b"%PDF-1.5 \n%Embedded clean document payload\n%%EOF"
    res = VbaMacroAnalyzer.analyze_attachment("annual_report.pdf", clean_bytes, "sha256_pdf")
    assert res.has_macros is False
    assert res.is_malicious is False
    assert res.macro_count == 0
    assert len(res.triggers) == 0


def test_vba_macro_analyzer_corrupt_file():
    """Verify malformed or corrupted files do not crash the analyzer."""
    corrupt_bytes = b"PK\x03\x04corrupted_zip_stream_bytes_here"
    res = VbaMacroAnalyzer.analyze_attachment("invoice.xlsm", corrupt_bytes, "sha256_corrupt")
    assert res.has_macros is False
    assert res.is_malicious is False


def test_vba_macro_analyzer_weaponized_mock():
    """Verify that when VBA macros contain AutoExec and Shell/PowerShell, is_malicious is True."""
    dummy_bytes = b"PK\x03\x04dummy_macro_container"

    mock_vba = MagicMock()
    mock_vba.detect_vba_macros.return_value = True
    mock_vba.extract_macros.return_value = [
        ("invoice.docm", "VBA/ThisDocument", "ThisDocument", (
            "Sub AutoOpen()\n"
            "  Dim url As String\n"
            "  url = \"http://c2-malware.evil/loader.exe\"\n"
            "  Shell(\"powershell.exe -ExecutionPolicy Bypass -Command ...\")\n"
            "End Sub\n"
        ))
    ]
    mock_vba.analyze_macros.return_value = [
        ("AutoExec", "AutoOpen", "Runs when the document is opened"),
        ("Suspicious", "Shell", "May run an executable file or a system command"),
        ("Suspicious", "PowerShell", "May run PowerShell commands"),
        ("IOC", "http://c2-malware.evil/loader.exe", "URL"),
    ]

    with patch("app.forensics.macro_analyzer.VBA_Parser", return_value=mock_vba):
        res = VbaMacroAnalyzer.analyze_attachment("invoice.docm", dummy_bytes, "dummy_sha256")

        assert res.has_macros is True
        assert res.is_malicious is True
        assert res.macro_count == 1
        assert "AutoOpen" in res.triggers
        assert any(k.keyword == "Shell" for k in res.suspicious_keywords)
        assert any(ioc["value"] == "http://c2-malware.evil/loader.exe" for ioc in res.extracted_iocs)
        assert "AutoOpen" in res.code_preview
        assert mock_vba.close.called


def test_suspicious_attachment_detector_elevates_weaponized_macro():
    """Verify SuspiciousAttachmentDetector elevates severity to critical for weaponized macros."""
    detector = SuspiciousAttachmentDetector()

    att = AttachmentData(
        filename="malicious_macro.xlsm",
        content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
        size=1024,
        sha256="abc123sha",
        is_macro=True,
        is_inline=False,
        content_id=None,
        raw_bytes=b"PK\x03\x04dummy_data",
    )

    parsed = ParsedEmailResult(
        headers={"subject": "Invoices"},
        body_text="Please enable macros to view.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[att],
        urls=[],
        auth_results={},
        received_chain=[],
    )

    mock_res = MacroAnalysisResult(
        filename="malicious_macro.xlsm",
        sha256="abc123sha",
        has_macros=True,
        is_malicious=True,
        macro_count=1,
        triggers=["Workbook_Open"],
        suspicious_keywords=[
            SuspiciousKeyword(type="AutoExec", keyword="Workbook_Open", description="Auto run"),
            SuspiciousKeyword(type="Suspicious", keyword="Shell", description="Run command"),
        ],
        extracted_iocs=[{"type": "URL", "value": "http://evil.com/dropper.exe"}],
        code_preview="Sub Workbook_Open()\n  Shell(\"calc.exe\")\nEnd Sub",
    )

    with patch("app.forensics.macro_analyzer.VbaMacroAnalyzer.analyze_attachment", return_value=mock_res):
        findings = detector.analyze(parsed)

    critical_findings = [f for f in findings if f.severity == SeverityLevel.critical]
    assert len(critical_findings) >= 1
    assert "Weaponized VBA Macro Attachment" in critical_findings[0].title
    assert "Workbook_Open" in critical_findings[0].detail
