import hashlib
import json
import uuid
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_analyst
from app.config import settings
from app.database import get_db
from app.correlation.campaign_clusterer import CampaignClusterer
from app.export.ioc_exporter import IocExportEngine
from app.models.case import Case, CaseStatus
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.parsed_email import ParsedEmail
from app.models.report import Report, ReportFormat
from app.reporting.generator import ForensicReportGenerator
from app.response.playbook_generator import PlaybookGenerator
from app.schemas.campaign import CaseCampaignAffiliation
from app.schemas.analysis import (
    AIAnalysisResponse,
    DomainIntelResponse,
    FinancialForensicsResponse,
    LiveDnsValidationResponse,
    MacroAnalysisListResponse,
    ObfuscationAnalysisResponse,
    OriginProfileResponse,
    PlaybookResponse,
    PlaybookToggleRequest,
    RiskScoreResponse,
    ThreatClassificationResponse,
)
from app.schemas.case import CaseDetail, CaseListResponse, CaseResponse
from app.schemas.finding import FindingListResponse
from app.schemas.indicator import IndicatorGraphResponse, IndicatorListResponse
from app.schemas.parsed_email import ParsedEmailResponse
from app.schemas.report import ReportListResponse, ReportResponse
from app.storage.base import EvidenceStore
from app.storage.deps import get_evidence_store
from app.tasks.queue import enqueue_case_analysis

router = APIRouter()


async def get_case_or_404(case_id: uuid.UUID, analyst_id: uuid.UUID, db: AsyncSession) -> Case:
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.analyst_id != analyst_id:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    content = await file.read()

    # Enforce maximum upload size
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_BYTES} bytes",
        )

    # Compute SHA-256 digest
    sha256_hash = hashlib.sha256(content).hexdigest()
    storage_key = f"cases/{sha256_hash}.eml"

    # Store byte-for-byte evidence in immutable storage
    await storage.put(storage_key, content)

    new_case = Case(
        original_sha256=sha256_hash,
        original_size=len(content),
        filename=file.filename,
        storage_key=storage_key,
        analyst_id=analyst_id,
        status=CaseStatus.pending,
    )

    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)

    # Enqueue background analysis job (RQ if available, else BackgroundTasks)
    queued = enqueue_case_analysis(new_case.id)
    if not queued:
        from app.tasks.jobs import _async_process_case
        background_tasks.add_task(_async_process_case, new_case.id)

    return new_case


@router.get("", response_model=CaseListResponse)
async def list_cases(
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Case).where(Case.analyst_id == analyst_id).order_by(Case.created_at.desc())
    )
    cases = result.scalars().all()
    items = []
    for c in cases:
        meta = c.metadata_json or {}
        tc = meta.get("threat_classification") or {}
        sc = meta.get("risk_score") or {}
        items.append(
            CaseResponse(
                id=c.id,
                status=c.status,
                original_sha256=c.original_sha256,
                original_size=c.original_size,
                filename=c.filename,
                created_at=c.created_at,
                updated_at=c.updated_at,
                threat_category=tc.get("primary_category"),
                category_label=tc.get("category_label"),
                risk_score=sc.get("score"),
            )
        )
    return {"items": items, "total": len(items)}


@router.get("/{id}", response_model=CaseDetail)
async def get_case(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    return case


@router.get("/{id}/parsed", response_model=ParsedEmailResponse)
async def get_parsed_email(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    result = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
    parsed_email = result.scalars().first()
    if not parsed_email:
        raise HTTPException(status_code=404, detail="Email has not been parsed yet")
    return parsed_email


@router.get("/{id}/attachments/{sha256}")
async def get_attachment_file(
    id: uuid.UUID,
    sha256: str,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)

    result = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
    parsed = result.scalars().first()
    if not parsed or not parsed.attachments_json:
        raise HTTPException(status_code=404, detail="Attachment not found")

    attachment_entry = None
    for att in parsed.attachments_json:
        if att.get("sha256") == sha256:
            attachment_entry = att
            break

    if not attachment_entry:
        raise HTTPException(status_code=404, detail="Attachment not found in case")

    storage_key = attachment_entry.get("storage_key") or f"cases/{case.original_sha256}/attachments/{sha256}"
    if not await storage.exists(storage_key):
        raise HTTPException(status_code=404, detail="Attachment file not found in storage")

    stream = storage.get_stream(storage_key)
    safe_filename = attachment_entry.get("filename", "attachment.bin").replace('"', '\\"')
    headers = {
        # Never trust declared MIME to avoid browser script execution (Security requirement)
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "X-Attachment-SHA256": sha256,
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(stream, media_type="application/octet-stream", headers=headers)


@router.get("/{id}/findings", response_model=FindingListResponse)
async def get_findings(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    result = await db.execute(select(Finding).where(Finding.case_id == case.id).order_by(Finding.created_at))
    items = result.scalars().all()
    return {"items": items, "total": len(items)}


@router.get("/{id}/indicators", response_model=IndicatorListResponse)
async def get_indicators(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    result = await db.execute(
        select(Indicator).where(Indicator.case_id == case.id).order_by(Indicator.first_seen_at)
    )
    items = result.scalars().all()
    return {"items": items, "total": len(items)}


@router.get("/{id}/graph", response_model=IndicatorGraphResponse)
async def get_indicator_graph(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    metadata = case.metadata_json or {}
    graph_data = metadata.get("indicator_graph")
    if graph_data:
        return graph_data
    return {"nodes": [], "edges": []}


@router.get("/{id}/score", response_model=RiskScoreResponse)
async def get_risk_score(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    metadata = case.metadata_json or {}
    score_data = metadata.get("risk_score")
    if score_data:
        return score_data

    return {
        "score": 0.0,
        "confidence": 0.0,
        "coverage": 0.0,
        "uncertainty_label": "not_yet_analyzed",
        "is_heuristic": True,
        "summary": "Case has not been analyzed yet.",
    }


@router.get("/{id}/ai-analysis", response_model=AIAnalysisResponse)
async def get_case_ai_analysis(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    metadata = case.metadata_json or {}
    ai_analysis = metadata.get("ai_analysis")
    if not ai_analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not yet generated for this case",
        )
    return ai_analysis


@router.get("/{id}/route")
async def get_case_route(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    metadata = case.metadata_json or {}
    return metadata.get(
        "route_analysis",
        {"hops": [], "total_transit_seconds": 0.0, "anomalies": []},
    )


@router.get("/{id}/qr-codes")
async def get_case_qr_codes(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    metadata = case.metadata_json or {}
    return metadata.get("qr_codes", [])


@router.post("/{id}/report", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    id: uuid.UUID,
    format: ReportFormat = Query(default=ReportFormat.html),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)

    # 1. Fetch parsed email structure if available
    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    # 2. Fetch all detection findings
    findings_res = await db.execute(
        select(Finding).where(Finding.case_id == id).order_by(Finding.created_at.desc())
    )
    findings = findings_res.scalars().all()

    # 3. Generate structured forensic report
    if format == ReportFormat.json:
        report_bytes, sha256_hash = ForensicReportGenerator.generate_json_report(
            case, parsed, findings, case.metadata_json
        )
    else:
        report_bytes, sha256_hash = ForensicReportGenerator.generate_html_report(
            case, parsed, findings, case.metadata_json
        )

    # 4. Save report in evidence storage
    report_id = uuid.uuid4()
    storage_key = f"reports/{case.id}/{report_id}.{format.value}"
    await storage.put(storage_key, report_bytes)

    # 5. Record report in PostgreSQL database
    db_report = Report(
        id=report_id,
        case_id=case.id,
        format=format,
        storage_key=storage_key,
        integrity_sha256=sha256_hash,
    )
    db.add(db_report)
    await db.commit()
    await db.refresh(db_report)

    return db_report


@router.get("/{id}/reports", response_model=ReportListResponse)
async def list_reports(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    stmt = select(Report).where(Report.case_id == id).order_by(Report.created_at.desc())
    res = await db.execute(stmt)
    reports = res.scalars().all()
    return ReportListResponse(items=list(reports), total=len(reports))


@router.get("/{id}/reports/{rid}")
async def download_report(
    id: uuid.UUID,
    rid: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)
    stmt = select(Report).where(Report.case_id == id, Report.id == rid)
    res = await db.execute(stmt)
    report = res.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not await storage.exists(report.storage_key):
        raise HTTPException(status_code=404, detail="Report file missing from evidence storage")

    content = await storage.get(report.storage_key)

    # Runtime cryptographic tamper verification
    calculated_sha = hashlib.sha256(content).hexdigest()
    if report.integrity_sha256 and calculated_sha != report.integrity_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report evidence tampering detected: cryptographic SHA-256 mismatch",
        )

    media_type = "text/html; charset=utf-8" if report.format == ReportFormat.html else "application/json"
    headers = {
        "X-Report-SHA256": calculated_sha,
        "Content-Disposition": f'inline; filename="case_{case.id}_report_{report.id}.{report.format.value}"',
    }
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/{id}/macros", response_model=MacroAnalysisListResponse)
async def get_case_macros(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    items = meta.get("macro_analysis", [])
    return MacroAnalysisListResponse(items=items, total=len(items))


@router.get("/{id}/obfuscation", response_model=ObfuscationAnalysisResponse)
async def get_case_obfuscation(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    obf_data = meta.get("obfuscation_analysis", {
        "has_evasion": False,
        "body": {},
        "subject": {},
    })
    return ObfuscationAnalysisResponse(**obf_data)


@router.get("/{id}/domain-intel", response_model=DomainIntelResponse)
async def get_case_domain_intel(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    domain_data = meta.get("domain_intel")
    if not domain_data:
        return DomainIntelResponse(domain="", risk_level="unknown", status=[])
    return DomainIntelResponse(**domain_data)


@router.get("/{id}/dns-validation", response_model=LiveDnsValidationResponse)
async def get_case_dns_validation(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    dns_data = meta.get("dns_validation")
    if not dns_data:
        return LiveDnsValidationResponse(
            domain="",
            dns_resolved=False,
            spf={},
            dmarc={},
            mx={},
            alignment={},
            message_id_valid=True,
            anomalies=[],
        )
    return LiveDnsValidationResponse(**dns_data)


@router.get("/{id}/origin-profile", response_model=OriginProfileResponse)
async def get_case_origin_profile(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    origin_data = meta.get("origin_profile")
    if not origin_data:
        return OriginProfileResponse(origin_confidence="inconclusive")
    return OriginProfileResponse(**origin_data)


@router.get("/{id}/threat-category", response_model=ThreatClassificationResponse)
async def get_case_threat_category(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    data = meta.get("threat_classification")
    if not data:
        return ThreatClassificationResponse(
            primary_category="LEGITIMATE",
            category_label="Legitimate Business Communication",
            confidence=0.5,
            secondary_categories=[],
            justification=["Classification pending or not available."],
            action_summary="Routine email.",
        )
    return ThreatClassificationResponse(**data)


@router.get("/{id}/financial-forensics", response_model=FinancialForensicsResponse)
async def get_case_financial_forensics(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}
    data = meta.get("financial_forensics")
    if not data:
        return FinancialForensicsResponse(is_financial_threat=False, risk_level="none")
    return FinancialForensicsResponse(**data)


@router.get("/{id}/original")
async def get_original_file(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)

    if not await storage.exists(case.storage_key):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found in storage",
        )

    # Runtime SHA-256 integrity verification (Mitigating Threat T03)
    is_valid = await storage.verify_integrity(case.storage_key, case.original_sha256)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Evidence integrity violation: stored file hash does not match original SHA-256",
        )

    stream = storage.get_stream(case.storage_key)
    safe_filename = (case.filename or "evidence.eml").replace('"', '\\"')
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "X-Evidence-SHA256": case.original_sha256,
    }
    return StreamingResponse(stream, media_type="message/rfc822", headers=headers)


@router.get("/{id}/playbook", response_model=PlaybookResponse)
async def get_case_playbook(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    completed_ids = set(meta.get("completed_action_ids", []))

    return PlaybookGenerator.generate(
        case_id=str(case.id),
        parsed_email=parsed,
        threat_classification=meta.get("threat_classification"),
        financial_forensics=meta.get("financial_forensics"),
        origin_profile=meta.get("origin_profile"),
        dns_validation=meta.get("dns_validation"),
        completed_action_ids=completed_ids,
    )


@router.post("/{id}/playbook/toggle", response_model=PlaybookResponse)
async def toggle_playbook_action(
    id: uuid.UUID,
    payload: PlaybookToggleRequest,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = dict(case.metadata_json or {})
    completed_ids = set(meta.get("completed_action_ids", []))

    if payload.completed:
        completed_ids.add(payload.action_id)
    else:
        completed_ids.discard(payload.action_id)

    meta["completed_action_ids"] = list(completed_ids)
    case.metadata_json = meta
    flag_modified(case, "metadata_json")
    await db.commit()
    await db.refresh(case)

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    return PlaybookGenerator.generate(
        case_id=str(case.id),
        parsed_email=parsed,
        threat_classification=meta.get("threat_classification"),
        financial_forensics=meta.get("financial_forensics"),
        origin_profile=meta.get("origin_profile"),
        dns_validation=meta.get("dns_validation"),
        completed_action_ids=completed_ids,
    )


@router.get("/{id}/export/stix")
async def export_case_stix(
    id: uuid.UUID,
    download: bool = Query(default=False),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    findings_res = await db.execute(select(Finding).where(Finding.case_id == id))
    findings = findings_res.scalars().all()

    indicators_res = await db.execute(select(Indicator).where(Indicator.case_id == id))
    indicators = indicators_res.scalars().all()

    threat_class = meta.get("threat_classification")
    bundle = IocExportEngine.export_stix_bundle(
        case_id=str(case.id),
        parsed_email=parsed,
        findings=findings,
        indicators=indicators,
        threat_classification=threat_class,
    )
    content = json.dumps(bundle, indent=2)

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="MailRecon-{case.id}-stix2.1.json"'
    return Response(content=content, media_type="application/json", headers=headers)


@router.get("/{id}/export/yara")
async def export_case_yara(
    id: uuid.UUID,
    download: bool = Query(default=False),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    findings_res = await db.execute(select(Finding).where(Finding.case_id == id))
    findings = findings_res.scalars().all()

    content = IocExportEngine.export_yara_rule(
        case_id=str(case.id),
        parsed_email=parsed,
        findings=findings,
    )

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="MailRecon-{case.id}.yar"'
    return Response(content=content, media_type="text/plain; charset=utf-8", headers=headers)


@router.get("/{id}/export/sigma")
async def export_case_sigma(
    id: uuid.UUID,
    download: bool = Query(default=False),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    meta = case.metadata_json or {}

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    findings_res = await db.execute(select(Finding).where(Finding.case_id == id))
    findings = findings_res.scalars().all()

    content = IocExportEngine.export_sigma_rule(
        case_id=str(case.id),
        parsed_email=parsed,
        findings=findings,
        threat_classification=meta.get("threat_classification"),
    )

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="MailRecon-{case.id}-sigma.yml"'
    return Response(content=content, media_type="text/yaml; charset=utf-8", headers=headers)


@router.get("/{id}/export/snort")
async def export_case_snort(
    id: uuid.UUID,
    download: bool = Query(default=False),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)

    parsed_res = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == id))
    parsed = parsed_res.scalars().first()

    findings_res = await db.execute(select(Finding).where(Finding.case_id == id))
    findings = findings_res.scalars().all()

    content = IocExportEngine.export_snort_rules(
        case_id=str(case.id),
        parsed_email=parsed,
        findings=findings,
    )

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="MailRecon-{case.id}-suricata.rules"'
    return Response(content=content, media_type="text/plain; charset=utf-8", headers=headers)


@router.get("/{id}/campaign", response_model=CaseCampaignAffiliation)
async def get_case_campaign(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    cid_str = str(case.id)

    # Load all cases for clustering context
    stmt = (
        select(Case, ParsedEmail)
        .outerjoin(ParsedEmail, Case.id == ParsedEmail.case_id)
        .where(Case.analyst_id == analyst_id)
        .order_by(Case.created_at.desc())
    )
    res = await db.execute(stmt)
    rows = res.all()

    case_records = []
    for c, p in rows:
        case_records.append({
            "id": str(c.id),
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "filename": c.filename or f"Case_{str(c.id)[:8]}",
            "original_sha256": c.original_sha256,
            "metadata_json": c.metadata_json or {},
            "parsed_email": {
                "headers_json": p.headers_json if p else {},
                "attachments_json": p.attachments_json if p else [],
                "urls_json": p.urls_json if p else [],
                "body_text": p.body_text if p else "",
            } if p else {},
        })

    clusters = CampaignClusterer.cluster_cases(case_records)
    for c in clusters:
        case_ids_in_camp = [cs["case_id"] for cs in c.cases]
        if cid_str in case_ids_in_camp:
            affiliated = [cs for cs in c.cases if cs["case_id"] != cid_str]
            case_shared = [
                art for art in c.shared_artifacts if cid_str in art.get("case_ids", [])
            ]
            return CaseCampaignAffiliation(
                case_id=cid_str,
                is_part_of_campaign=True,
                campaign_id=c.campaign_id,
                campaign_name=c.name,
                threat_archetype=c.threat_archetype,
                total_correlated_cases=c.case_count,
                shared_artifacts=case_shared or c.shared_artifacts,
                affiliated_cases=affiliated,
                graph=c.graph,
            )

    return CaseCampaignAffiliation(
        case_id=cid_str,
        is_part_of_campaign=False,
        total_correlated_cases=1,
        shared_artifacts=[],
        affiliated_cases=[],
    )


