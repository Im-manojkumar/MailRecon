import email
from email.message import EmailMessage
from pathlib import Path
import pytest

from app.parser.email_parser import EmailParser
from app.parser.sanitizer import sanitize_html
from app.parser.urls import defang_url, extract_urls, is_ip_host
from tests.conftest import fixture_path


def test_parse_clean_simple():
    raw_bytes = fixture_path("clean_simple.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    assert "Meeting Tomorrow" in res.headers["subject"]
    assert "alice@example.com" in res.headers["from"]
    assert "bob@example.com" in res.headers["to"]
    assert "Are we still on for the meeting tomorrow?" in res.body_text

    # Verify Authentication-Results parsing and provenance
    assert res.auth_results["authserv_id"] == "mx.destination.com"
    assert res.auth_results["spf"]["result"] == "pass"
    assert res.auth_results["dkim"]["result"] == "pass"
    assert res.auth_results["dmarc"]["result"] == "pass"
    assert res.auth_results["provenance"] == "unverified_header_claim"

    # Verify Received hops
    assert len(res.received_chain) >= 1
    hop = res.received_chain[0]
    assert hop["hop_number"] == 1
    assert hop["ip"] == "192.0.2.1"
    assert hop["is_tls"] is True
    assert hop["protocol"] == "ESMTPS"


def test_parse_bec_urgent():
    raw_bytes = fixture_path("bec_urgent.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    assert "URGENT" in res.headers["subject"]
    assert res.headers["reply_to"] != ""
    assert "wire transfer" in res.body_text.lower()


def test_parse_phishing_url():
    raw_bytes = fixture_path("phishing_url.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    # 3 distinct target URLs in fixture: login link, IP link, main site link
    urls = [u["url"] for u in res.urls]
    assert any("login.example-secure.xyz" in u for u in urls)
    assert any("192.168.1.100" in u for u in urls)
    assert any("example.com" in u for u in urls)

    # Verify defanging & IP detection
    for u in res.urls:
        if "192.168.1.100" in u["url"]:
            assert u["is_ip"] is True
            assert "[.]" in u["defanged"]
            assert u["defanged"].startswith("hxxp://")
        elif "login.example-secure.xyz" in u["url"]:
            assert u["is_ip"] is False
            assert "[.]" in u["defanged"]
            assert u["defanged"].startswith("hxxps://")

    # Verify HTML body is sanitized
    assert "<script" not in res.body_html.lower()
    assert "href=" in res.body_html


def test_parse_spf_fail():
    raw_bytes = fixture_path("spf_fail.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    assert res.auth_results["spf"]["result"] == "fail"
    assert res.auth_results["dkim"]["result"] == "none"
    assert res.auth_results["dmarc"]["result"] == "fail"
    assert res.auth_results["provenance"] == "unverified_header_claim"


def test_parse_attachment_macro():
    raw_bytes = fixture_path("attachment_macro.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    assert len(res.attachments) == 1
    att = res.attachments[0]
    assert att.filename == "invoice_2024.xlsm"
    assert att.is_macro is True
    assert att.is_inline is False
    assert len(att.sha256) == 64
    assert att.size > 0
    assert "macroenabled" in att.content_type.lower()


def test_parse_multipart_nested():
    raw_bytes = fixture_path("multipart_nested.eml").read_bytes()
    res = EmailParser.parse(raw_bytes)

    assert "This is the plain text version." in res.body_text
    assert "HTML version with image" in res.body_html
    assert res.mime_depth_exceeded is False

    # Check extracted assets (logo.png inline, update.pdf attachment)
    filenames = [a.filename for a in res.attachments]
    assert "logo.png" in filenames
    assert "update.pdf" in filenames

    pdf_att = next(a for a in res.attachments if a.filename == "update.pdf")
    assert pdf_att.is_macro is False
    assert pdf_att.content_type == "application/pdf"


def test_html_sanitization_security():
    malicious_html = """
    <html>
        <body>
            <script>alert("pwned")</script>
            <p onclick="steal()">Click me</p>
            <a href="javascript:alert(1)">Evil Link</a>
            <iframe src="http://evil.com"></iframe>
            <img src="https://tracker.attacker.com/pixel.png" alt="tracker">
            <img src="cid:safe_inline_logo">
        </body>
    </html>
    """
    clean_html, blocked_images = sanitize_html(malicious_html)

    assert "<script" not in clean_html
    assert "onclick" not in clean_html
    assert "javascript:" not in clean_html
    assert "<iframe" not in clean_html
    # Remote tracker was neutralized
    assert "https://tracker.attacker.com/pixel.png" in blocked_images
    assert "data-blocked=\"true\"" in clean_html
    assert "data:image/svg+xml" in clean_html
    # Inline cid: was preserved
    assert 'src="cid:safe_inline_logo"' in clean_html


def test_url_defanging():
    assert defang_url("http://example.com") == "hxxp://example[.]com"
    assert defang_url("https://sub.domain.co.uk/path?q=1") == "hxxps://sub[.]domain[.]co[.]uk/path?q=1"
    assert defang_url("http://192.168.1.1/cmd.exe") == "hxxp://192[.]168[.]1[.]1/cmd.exe"


def test_ip_host_detection():
    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.1:8080") is True
    assert is_ip_host("example.com") is False
    assert is_ip_host("login.bad-domain.xyz") is False


def test_mime_recursion_limit():
    """Verify that a deeply nested MIME structure triggers recursion cutoff safely."""
    outermost = EmailMessage()
    outermost["Subject"] = "Nested MIME Bomb Test"
    outermost["From"] = "test@nested.com"
    outermost["To"] = "victim@test.com"

    curr = outermost
    for _ in range(15):  # 15 levels > MAX_MIME_DEPTH (10)
        sub = EmailMessage()
        curr.set_content(sub)
        curr = sub

    curr.set_content("Deeply buried payload")

    res = EmailParser.parse(outermost.as_bytes())
    assert res.mime_depth_exceeded is True
