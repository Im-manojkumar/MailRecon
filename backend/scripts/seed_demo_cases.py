"""
Seed demo forensic cases and threat campaigns into MailRecon database.

Usage:
    cd backend
    python -m scripts.seed_demo_cases
"""

import asyncio
import hashlib
import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone

# Ensure backend root is on Python path
CURRENT_DIR = pathlib.Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import select
from app.database import engine, async_session_maker, Base
from app.models.analyst import Analyst
from app.models.case import Case, CaseStatus
from app.auth import hash_password
from app.storage.deps import get_evidence_store
from app.tasks.jobs import _async_process_case

DEMO_ANALYST_EMAIL = "analyst@mailrecon.local"
DEMO_ANALYST_PASSWORD = "Password123!"

# Realistic second BEC case sharing IBAN with bec_urgent.eml to form a live campaign
LINKED_PAYMENT_DIVERSION_EML = """Received: from mail.payroll-finance-update.com (mail.payroll-finance-update.com [198.51.100.22])
	by mx.enterprise-corp.com (Postfix) with ESMTP id 8B72D409A1
	for <cfo@enterprise-corp.com>; Thu, 10 Sep 2026 14:15:00 +0000
Received: from 192.168.1.50 (unknown [185.220.101.5])
	by mail.payroll-finance-update.com with HTTP;
	Thu, 10 Sep 2026 14:14:30 +0000
From: "Controller Office" <billing@payroll-finance-update.com>
To: <cfo@enterprise-corp.com>
Reply-To: <settlements@payroll-finance-update.com>
Subject: URGENT: Q3 Vendor Settlement & Updated Banking Coordinates
Date: Thu, 10 Sep 2026 14:14:00 +0000
Message-ID: <20260910141400.8B72D409A1@payroll-finance-update.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Executive Team,

Please be advised that effective immediately, all outstanding Q3 enterprise retainer settlements and pending invoices must be routed to our newly designated European treasury account due to an ongoing banking transition.

Please execute the wire transfer of $84,500.00 today to prevent service interruption.

Beneficiary Bank: National Westminster Bank London
IBAN: GB29NWBK60161331926819
Routing / ABA: 021000021
SWIFT / BIC: NWBKGB2L

Ensure all future billing remittances are directed solely to these coordinates. Do not call the previous office number as phone lines are currently undergoing telecommunication maintenance.

Regards,
Financial Controller & Accounts Payable
"""


async def seed_demo():
    print("=" * 70)
    print("MailRecon - Seeding Demo Forensic Evidence & Campaigns")
    print("=" * 70)

    # 1. Ensure DB tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[+] Database schema verified.")

    # 2. Ensure default demo analyst exists
    async with async_session_maker() as session:
        result = await session.execute(select(Analyst).where(Analyst.email == DEMO_ANALYST_EMAIL))
        analyst = result.scalars().first()
        if not analyst:
            analyst = Analyst(
                email=DEMO_ANALYST_EMAIL,
                hashed_password=hash_password(DEMO_ANALYST_PASSWORD),
                display_name="Forensic Lead Analyst",
                is_active=True,
            )
            session.add(analyst)
            await session.commit()
            await session.refresh(analyst)
            print(f"[+] Created demo analyst: {DEMO_ANALYST_EMAIL} (Password: {DEMO_ANALYST_PASSWORD})")
        else:
            print(f"[*] Demo analyst already exists: {DEMO_ANALYST_EMAIL}")
        analyst_id = analyst.id

    # 3. Load fixtures
    fixtures_dir = BACKEND_DIR / "tests" / "fixtures"
    fixture_files = list(fixtures_dir.glob("*.eml")) if fixtures_dir.exists() else []

    storage = get_evidence_store()
    ingested_cases = []

    # Ingest standard fixtures
    for fix_path in fixture_files:
        content = fix_path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        storage_key = f"cases/{sha256}.eml"
        await storage.put(storage_key, content)

        async with async_session_maker() as session:
            # Check if already exists
            res = await session.execute(select(Case).where(Case.original_sha256 == sha256))
            existing = res.scalars().first()
            if not existing:
                case = Case(
                    original_sha256=sha256,
                    original_size=len(content),
                    filename=fix_path.name,
                    storage_key=storage_key,
                    analyst_id=analyst_id,
                    status=CaseStatus.pending,
                )
                session.add(case)
                await session.commit()
                await session.refresh(case)
                ingested_cases.append((case.id, fix_path.name))
            else:
                print(f"[*] Case {fix_path.name} already in database ({existing.id})")

    # Ingest linked campaign case (shares IBAN with bec_urgent.eml)
    linked_bytes = LINKED_PAYMENT_DIVERSION_EML.encode("utf-8")
    linked_sha = hashlib.sha256(linked_bytes).hexdigest()
    linked_storage_key = f"cases/{linked_sha}.eml"
    await storage.put(linked_storage_key, linked_bytes)

    async with async_session_maker() as session:
        res = await session.execute(select(Case).where(Case.original_sha256 == linked_sha))
        existing = res.scalars().first()
        if not existing:
            case = Case(
                original_sha256=linked_sha,
                original_size=len(linked_bytes),
                filename="bec_wire_invoice_update.eml",
                storage_key=linked_storage_key,
                analyst_id=analyst_id,
                status=CaseStatus.pending,
            )
            session.add(case)
            await session.commit()
            await session.refresh(case)
            ingested_cases.append((case.id, "bec_wire_invoice_update.eml"))
            print("[+] Added correlated campaign case: bec_wire_invoice_update.eml")

    # 4. Run full analysis pipeline on new cases
    print(f"\n[+] Analyzing {len(ingested_cases)} ingested forensic cases...")
    for c_id, name in ingested_cases:
        print(f"    -> Processing {name} ({c_id})...", end="", flush=True)
        success = await _async_process_case(c_id)
        if success:
            print(" DONE")
        else:
            print(" FAILED")

    print("\n" + "=" * 70)
    print("Seed Complete! You can now log into the web dashboard:")
    print(f"URL:      http://localhost:3000")
    print(f"Username: {DEMO_ANALYST_EMAIL}")
    print(f"Password: {DEMO_ANALYST_PASSWORD}")
    print("Features ready for inspection:")
    print("  - Live Threat Archetype classifications and Origin Traceability")
    print("  - Financial Forensics & Payment Diversion detection")
    print("  - Incident Response Playbooks & Multi-Format IOC Exporters (STIX, YARA, Sigma, Snort)")
    print("  - Correlated Multi-Case Threat Campaigns at /campaigns")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(seed_demo())
