import pytest
import json
from app.export.ioc_exporter import IocExportEngine


class DummyIndicator:
    def __init__(self, ind_type, value):
        self.type = ind_type
        self.value = value


class DummyFinding:
    def __init__(self, title, detector, severity, detail):
        self.title = title
        self.detector = detector
        self.severity = severity
        self.detail = detail


class DummyParsedEmail:
    def __init__(self):
        self.headers_json = {
            "from": "bad-actor@evil-phish.biz",
            "subject": "Wire Transfer Request",
            "message-id": "<xyz999@evil-phish.biz>",
        }
        self.body_text = "Please send payment to our updated bank account."
        self.urls_json = [
            {"url": "http://evil-phish.biz/login", "domain": "evil-phish.biz"}
        ]
        self.attachments_json = [
            {"filename": "malware.docm", "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}
        ]


def test_stix_bundle_export():
    parsed = DummyParsedEmail()
    findings = [
        DummyFinding("Phishing URL Detected", "url_detector", "critical", "Found malicious URL http://evil-phish.biz/login")
    ]
    indicators = [
        DummyIndicator("domain", "evil-phish.biz"),
        DummyIndicator("url", "http://evil-phish.biz/login"),
        DummyIndicator("ip", "198.51.100.44"),
        DummyIndicator("hash", "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"),
    ]
    threat_class = {"primary_category": "CREDENTIAL_PHISHING", "confidence": 0.9}

    bundle = IocExportEngine.export_stix_bundle(
        case_id="case-123",
        parsed_email=parsed,
        findings=findings,
        indicators=indicators,
        threat_classification=threat_class,
    )

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    assert len(objects) >= 3

    identity = [o for o in objects if o["type"] == "identity"][0]
    assert identity["name"] == "Mail-Recon AI Automated Forensic Engine"

    stix_indicators = [o for o in objects if o["type"] == "indicator"]
    assert len(stix_indicators) >= 4
    patterns = [ind["pattern"] for ind in stix_indicators]
    assert any("[domain-name:value =" in p for p in patterns)
    assert any("[url:value =" in p for p in patterns)
    assert any("[ipv4-addr:value =" in p for p in patterns)
    assert any("[file:hashes.'SHA-256' =" in p for p in patterns)


def test_yara_rule_export():
    parsed = DummyParsedEmail()
    findings = [DummyFinding("Suspicious Macro", "macro_analyzer", "high", "Macro execution")]

    rule_text = IocExportEngine.export_yara_rule(
        case_id="case-abc-456",
        parsed_email=parsed,
        findings=findings,
    )

    assert "rule MailRecon_Threat_Hunting_case_abc_456" in rule_text
    assert "meta:" in rule_text
    assert "strings:" in rule_text
    assert "condition:" in rule_text
    assert "$subject =" in rule_text
    assert "Wire Transfer Request" in rule_text
    assert "$sender =" in rule_text
    assert "bad-actor@evil-phish.biz" in rule_text
    assert "$url_0 = \"http://evil-phish.biz/login\"" in rule_text


def test_sigma_rule_export():
    parsed = DummyParsedEmail()
    findings = [DummyFinding("BEC Detected", "bec_detector", "high", "Impersonation alert")]
    threat_class = {"primary_category": "PAYMENT_DIVERSION"}

    sigma_yaml = IocExportEngine.export_sigma_rule(
        case_id="case-xyz-789",
        parsed_email=parsed,
        findings=findings,
        threat_classification=threat_class,
    )

    assert "title: Mail-Recon Detection - Wire Transfer Request" in sigma_yaml
    assert "status: experimental" in sigma_yaml
    assert "logsource:" in sigma_yaml
    assert "category: email" in sigma_yaml
    assert "detection:" in sigma_yaml
    assert "evil-phish.biz" in sigma_yaml
    assert "condition: 1 of selection_*" in sigma_yaml
    assert "level: high" in sigma_yaml


def test_snort_rule_export():
    parsed = DummyParsedEmail()
    findings = []

    snort_rules = IocExportEngine.export_snort_rules(
        case_id="case-net-111",
        parsed_email=parsed,
        findings=findings,
    )

    assert "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS" in snort_rules
    assert "content:\"evil-phish.biz\"" in snort_rules
    assert "classtype:trojan-activity" in snort_rules
    assert "sid:" in snort_rules
