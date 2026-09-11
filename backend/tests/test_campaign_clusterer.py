import pytest
from app.correlation.campaign_clusterer import CampaignClusterer


def test_cluster_shared_iban():
    case1 = {
        "id": "11111111-1111-1111-1111-111111111111",
        "filename": "invoice_october.eml",
        "created_at": "2026-09-01T10:00:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "accounting@supplier-alpha.com",
                "to": "cfo@company.org",
                "subject": "Updated October Invoice",
            },
            "attachments_json": [],
            "urls_json": [],
        },
        "metadata_json": {
            "threat_classification": {
                "primary_category": "PAYMENT_DIVERSION",
                "category_label": "Payment Diversion / Wire Fraud",
                "confidence": 0.95,
            },
            "financial_forensics": {
                "is_financial_threat": True,
                "bank_accounts": ["GB82WEST12345698765432"],
                "routing_numbers": ["021000021"],
            },
            "risk_score": {"score": 0.90},
        },
    }

    case2 = {
        "id": "22222222-2222-2222-2222-222222222222",
        "filename": "remittance_change.eml",
        "created_at": "2026-09-02T14:30:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "billing@different-vendor.com",
                "to": "treasury@company.org",
                "subject": "URGENT: Change of Banking Details",
            },
            "attachments_json": [],
            "urls_json": [],
        },
        "metadata_json": {
            "threat_classification": {
                "primary_category": "PAYMENT_DIVERSION",
                "category_label": "Payment Diversion / Wire Fraud",
                "confidence": 0.92,
            },
            "financial_forensics": {
                "is_financial_threat": True,
                "bank_accounts": ["GB82WEST12345698765432"],
            },
            "risk_score": {"score": 0.88},
        },
    }

    clusters = CampaignClusterer.cluster_cases([case1, case2])
    assert len(clusters) == 1
    camp = clusters[0]

    assert camp.case_count == 2
    assert camp.threat_category == "PAYMENT_DIVERSION"
    assert "Payment Diversion" in camp.name or "SilverWire" in camp.name
    assert any(a["kind"] == "iban" and a["value"] == "GB82WEST12345698765432" for a in camp.shared_artifacts)
    assert len(camp.graph["nodes"]) >= 3  # 2 case nodes + 1 artifact node


def test_cluster_shared_sender_domain():
    case1 = {
        "id": "33333333-3333-3333-3333-333333333333",
        "filename": "password_alert.eml",
        "created_at": "2026-09-05T08:00:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "support@m365-security-portal.biz",
                "to": "alice@company.org",
                "subject": "Action Required: Password Expired",
            },
            "urls_json": [{"url": "http://m365-security-portal.biz/auth", "domain": "m365-security-portal.biz"}],
        },
        "metadata_json": {
            "threat_classification": {
                "primary_category": "CREDENTIAL_PHISHING",
                "confidence": 0.89,
            },
            "risk_score": {"score": 0.85},
        },
    }

    case2 = {
        "id": "44444444-4444-4444-4444-444444444444",
        "filename": "mfa_reset.eml",
        "created_at": "2026-09-06T11:00:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "admin@m365-security-portal.biz",
                "to": "bob@company.org",
                "subject": "MFA Configuration Notice",
            },
            "urls_json": [{"url": "http://m365-security-portal.biz/auth", "domain": "m365-security-portal.biz"}],
        },
        "metadata_json": {
            "threat_classification": {
                "primary_category": "CREDENTIAL_PHISHING",
                "confidence": 0.91,
            },
            "risk_score": {"score": 0.87},
        },
    }

    clusters = CampaignClusterer.cluster_cases([case1, case2])
    assert len(clusters) == 1
    camp = clusters[0]
    assert camp.threat_category == "CREDENTIAL_PHISHING"
    assert any(a["kind"] == "domain" and a["value"] == "m365-security-portal.biz" for a in camp.shared_artifacts)


def test_generic_email_domains_not_clustered():
    # Two independent emails from generic @gmail.com without shared IP or artifacts should not be clustered
    case1 = {
        "id": "55555555-5555-5555-5555-555555555555",
        "filename": "spam1.eml",
        "created_at": "2026-09-01T10:00:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "user123@gmail.com",
                "to": "charlie@company.org",
                "subject": "Newsletter 1",
            }
        },
        "metadata_json": {
            "threat_classification": {"primary_category": "SPAM_RECONNAISSANCE"},
            "risk_score": {"score": 0.15},
        },
    }

    case2 = {
        "id": "66666666-6666-6666-6666-666666666666",
        "filename": "spam2.eml",
        "created_at": "2026-09-02T10:00:00Z",
        "parsed_email": {
            "headers_json": {
                "from": "random999@gmail.com",
                "to": "dave@company.org",
                "subject": "Discount Deals",
            }
        },
        "metadata_json": {
            "threat_classification": {"primary_category": "SPAM_RECONNAISSANCE"},
            "risk_score": {"score": 0.12},
        },
    }

    clusters = CampaignClusterer.cluster_cases([case1, case2])
    assert len(clusters) == 0  # Not clustered because gmail.com is in EXCLUDED_GENERIC_DOMAINS


def test_shared_malware_hash():
    case1 = {
        "id": "77777777-7777-7777-7777-777777777777",
        "filename": "doc1.eml",
        "created_at": "2026-09-03T10:00:00Z",
        "parsed_email": {
            "headers_json": {"from": "sender1@domain-a.org", "subject": "Doc 1"},
            "attachments_json": [{"filename": "contract.docm", "sha256": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"}],
        },
        "metadata_json": {
            "threat_classification": {"primary_category": "MALWARE_DELIVERY"},
            "risk_score": {"score": 0.95},
        },
    }

    case2 = {
        "id": "88888888-8888-8888-8888-888888888888",
        "filename": "doc2.eml",
        "created_at": "2026-09-04T10:00:00Z",
        "parsed_email": {
            "headers_json": {"from": "sender2@domain-b.org", "subject": "Doc 2"},
            "attachments_json": [{"filename": "invoice.docm", "sha256": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"}],
        },
        "metadata_json": {
            "threat_classification": {"primary_category": "MALWARE_DELIVERY"},
            "risk_score": {"score": 0.93},
        },
    }

    clusters = CampaignClusterer.cluster_cases([case1, case2])
    assert len(clusters) == 1
    assert clusters[0].threat_category == "MALWARE_DELIVERY"
    assert any(a["kind"] == "hash" for a in clusters[0].shared_artifacts)
