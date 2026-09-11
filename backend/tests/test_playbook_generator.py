import pytest
from app.response.playbook_generator import PlaybookGenerator, ResponsePillar, ActionPriority


class DummyParsedEmail:
    def __init__(self, from_addr="attacker@phish-evil.com", subject="Urgent Wire Update", message_id="<msg-123@phish-evil.com>", sender_ip="198.51.100.22", recipient="victim@corporate.org"):
        self.headers_json = {
            "from": from_addr,
            "subject": subject,
            "message-id": message_id,
            "to": recipient,
        }
        self.body_text = "Please send payment to our new bank account."
        self.attachments_json = [
            {"filename": "invoice_malicious.exe", "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}
        ]
        self.urls_json = [
            {"url": "http://evil-phish.com/login", "domain": "evil-phish.com"}
        ]


def test_playbook_payment_diversion():
    parsed = DummyParsedEmail()
    threat_class = {
        "primary_category": "PAYMENT_DIVERSION",
        "category_label": "Payment Diversion / Wire Fraud",
        "confidence": 0.95,
    }
    financial = {
        "is_financial_threat": True,
        "bank_accounts": ["GB82WEST12345698765432"],
        "routing_numbers": ["021000021"],
        "swift_codes": ["CHASUS33"],
        "crypto_wallets": [],
    }

    pb = PlaybookGenerator.generate(
        case_id="case-001",
        parsed_email=parsed,
        threat_classification=threat_class,
        financial_forensics=financial,
    )

    assert pb.case_id == "case-001"
    assert pb.total_actions > 0
    assert pb.critical_actions > 0

    pillars = {item.pillar for item in pb.items}
    assert ResponsePillar.FINANCIAL_LEGAL.value in pillars
    assert ResponsePillar.EMAIL_GATEWAY.value in pillars

    fin_actions = [i for i in pb.items if i.pillar == ResponsePillar.FINANCIAL_LEGAL.value]
    assert any("Freeze" in i.title for i in fin_actions)
    assert any("GB82WEST12345698765432" in i.target_asset for i in fin_actions)


def test_playbook_credential_phishing():
    parsed = DummyParsedEmail(from_addr="support@fakemicrosoft.com", subject="Verify M365 Credentials")
    threat_class = {
        "primary_category": "CREDENTIAL_PHISHING",
        "category_label": "Credential Phishing",
        "confidence": 0.90,
    }

    pb = PlaybookGenerator.generate(
        case_id="case-002",
        parsed_email=parsed,
        threat_classification=threat_class,
    )

    pillars = {item.pillar for item in pb.items}
    assert ResponsePillar.IDENTITY_IAM.value in pillars
    assert ResponsePillar.EMAIL_GATEWAY.value in pillars

    iam_actions = [i for i in pb.items if i.pillar == ResponsePillar.IDENTITY_IAM.value]
    assert any("Revoke" in i.title for i in iam_actions)
    assert any("Revoke-AzureADUserAllRefreshToken" in (i.automated_script or "") for i in iam_actions)


def test_playbook_malware_delivery():
    parsed = DummyParsedEmail()
    threat_class = {
        "primary_category": "MALWARE_DELIVERY",
        "category_label": "Malware Delivery",
        "confidence": 0.88,
    }

    pb = PlaybookGenerator.generate(
        case_id="case-003",
        parsed_email=parsed,
        threat_classification=threat_class,
    )

    edr_actions = [i for i in pb.items if i.pillar == ResponsePillar.ENDPOINT_EDR.value]
    assert len(edr_actions) > 0
    assert any("invoice_malicious.exe" in i.target_asset for i in edr_actions)
    assert any("Defender" in (i.automated_script or "") for i in edr_actions)


def test_playbook_anonymized_origin():
    parsed = DummyParsedEmail()
    origin_profile = {
        "originating_ip": "185.220.101.5",
        "is_anonymized": True,
        "infra_label": "TOR Exit Node (The Onion Router)",
        "origin_confidence": "high",
    }

    pb = PlaybookGenerator.generate(
        case_id="case-004",
        parsed_email=parsed,
        origin_profile=origin_profile,
    )

    actions_with_ip = [i for i in pb.items if "185.220.101.5" in i.target_asset]
    assert len(actions_with_ip) > 0
    assert any("TOR Exit Node" in i.description for i in actions_with_ip)


def test_playbook_completed_toggle():
    parsed = DummyParsedEmail()
    threat_class = {"primary_category": "CREDENTIAL_PHISHING"}

    pb_initial = PlaybookGenerator.generate(
        case_id="case-005",
        parsed_email=parsed,
        threat_classification=threat_class,
    )
    first_action_id = pb_initial.items[0].action_id

    pb_updated = PlaybookGenerator.generate(
        case_id="case-005",
        parsed_email=parsed,
        threat_classification=threat_class,
        completed_action_ids={first_action_id},
    )

    assert pb_updated.completed_actions == 1
    toggled = [i for i in pb_updated.items if i.action_id == first_action_id][0]
    assert toggled.completed is True
