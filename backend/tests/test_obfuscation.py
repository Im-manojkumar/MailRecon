from pathlib import Path
import pytest
from httpx import AsyncClient

from app.detectors.bec_intent import BecIntentDetector
from app.detectors.evasive_obfuscation import EvasiveObfuscationDetector
from app.forensics.obfuscation import ObfuscationAnalyzer
from app.models.finding import SeverityLevel
from app.parser.email_parser import EmailParser
from tests.conftest import fixture_path, get_test_session_factory
from app.storage.deps import get_evidence_store
import app.tasks.jobs as jobs_module


def test_zero_width_detection_and_stripping():
    """Verify zero-width characters are detected and cleanly stripped."""
    spliced_word = "p\u200ba\u200by\u200bp\u200ba\u200bl"
    res = ObfuscationAnalyzer.analyze_text(spliced_word)

    assert res.has_evasion is True
    assert res.zero_width_count == 5
    assert res.normalized_text == "paypal"
    assert len(res.zero_width_chars) == 5
    assert res.zero_width_chars[0]["name"] == "ZERO WIDTH SPACE"


def test_rlo_detection_in_filename():
    """Verify Right-to-Left Override in filenames is flagged and sanitized."""
    rlo_name = "Quarterly_Report_\u202Efdp.exe"
    is_evasive, sanitized, trick = ObfuscationAnalyzer.inspect_filename(rlo_name)

    assert is_evasive is True
    assert sanitized == "Quarterly_Report_fdp.exe"
    assert "Right-To-Left" in trick


def test_homoglyph_detection_and_normalization():
    """Verify Cyrillic lookalikes are detected and mapped to canonical ASCII."""
    # Cyrillic 'а' is \u0430, 'о' is \u043e
    spoofed = "P\u0430yp\u0430l Micr\u043es\u043eft"
    res = ObfuscationAnalyzer.analyze_text(spoofed)

    assert res.has_evasion is True
    assert res.homoglyphs_detected is True
    assert res.normalized_text == "Paypal Microsoft"
    assert len(res.mixed_script_tokens) >= 2


def test_evasive_obfuscation_detector_on_zerowidth_fixture():
    """Verify detector catches zero-width keyword evasion in subject and body."""
    eml_bytes = Path(fixture_path("obfuscated_zerowidth.eml")).read_bytes()
    parsed = EmailParser.parse(eml_bytes)

    detector = EvasiveObfuscationDetector()
    findings = detector.analyze(parsed)

    assert len(findings) >= 1
    titles = [f.title for f in findings]
    assert any("Zero-Width" in t or "Invisible" in t for t in titles)
    assert any(f.severity == SeverityLevel.high for f in findings)


def test_evasive_obfuscation_detector_on_homoglyph_fixture():
    """Verify detector flags mixed-script homoglyphs in sender and subject."""
    eml_bytes = Path(fixture_path("obfuscated_homoglyph.eml")).read_bytes()
    parsed = EmailParser.parse(eml_bytes)

    detector = EvasiveObfuscationDetector()
    findings = detector.analyze(parsed)

    assert len(findings) >= 1
    titles = [f.title for f in findings]
    assert any("Homoglyph" in t for t in titles)
    assert any(f.severity == SeverityLevel.high for f in findings)


def test_evasive_obfuscation_detector_on_rlo_fixture():
    """Verify detector flags RLO character in attachment filenames as Critical."""
    eml_bytes = Path(fixture_path("attachment_rlo.eml")).read_bytes()
    parsed = EmailParser.parse(eml_bytes)

    detector = EvasiveObfuscationDetector()
    findings = detector.analyze(parsed)

    rlo_findings = [f for f in findings if "Right-to-Left Override" in f.title]
    assert len(rlo_findings) >= 1
    assert rlo_findings[0].severity == SeverityLevel.critical


def test_bec_detector_unmasked_by_deobfuscation():
    """Verify that BEC detector successfully unmasks zero-width obfuscated keywords."""
    eml_bytes = Path(fixture_path("obfuscated_zerowidth.eml")).read_bytes()
    parsed = EmailParser.parse(eml_bytes)

    bec_detector = BecIntentDetector()
    findings = bec_detector.analyze(parsed)

    assert len(findings) >= 1
    assert "Business Email Compromise (BEC)" in findings[0].title
    assert any("wire" in ind and "transfer" in ind for ind in findings[0].raw_evidence["financial_indicators"])


@pytest.mark.asyncio
async def test_macros_and_obfuscation_api_endpoints(
    async_client: AsyncClient,
    auth_headers: dict,
):
    """Verify /api/cases/{id}/macros and /api/cases/{id}/obfuscation REST endpoints."""
    from app.main import app
    session_factory = get_test_session_factory()
    storage = app.dependency_overrides[get_evidence_store]()

    orig_factory = jobs_module.async_session_maker
    orig_store = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: storage

    try:
        # 1. Upload case
        file_path = fixture_path("obfuscated_zerowidth.eml")
        with open(file_path, "rb") as f:
            resp = await async_client.post(
                "/api/cases",
                files={"file": ("obfuscated_zerowidth.eml", f, "message/rfc822")},
                headers=auth_headers,
            )
        assert resp.status_code == 201
        case_id = resp.json()["id"]

        # 2. Trigger worker processing synchronously
        import uuid
        processed = await jobs_module._async_process_case(uuid.UUID(case_id))
        assert processed is True

        # 3. Test /api/cases/{id}/macros
        mac_resp = await async_client.get(f"/api/cases/{case_id}/macros", headers=auth_headers)
        assert mac_resp.status_code == 200
        mac_data = mac_resp.json()
        assert "items" in mac_data
        assert "total" in mac_data

        # 4. Test /api/cases/{id}/obfuscation
        obf_resp = await async_client.get(f"/api/cases/{case_id}/obfuscation", headers=auth_headers)
        assert obf_resp.status_code == 200
        obf_data = obf_resp.json()
        assert obf_data["has_evasion"] is True
        assert obf_data["body"]["zero_width_count"] > 0
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store
