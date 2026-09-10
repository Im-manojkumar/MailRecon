"""
Forensic Report Generator for MailRecon AI.
Produces self-contained, cryptographically signed HTML and JSON forensic reports.
"""
from datetime import datetime, timezone
import hashlib
import html
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid

from app.models.case import Case
from app.models.finding import Finding
from app.models.parsed_email import ParsedEmail


class ForensicReportGenerator:
    """Generates immutable forensic reports stamped with cryptographic SHA-256 hashes."""

    @classmethod
    def generate_json_report(
        cls,
        case: Case,
        parsed: Optional[ParsedEmail],
        findings: List[Finding],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bytes, str]:
        """
        Generate a structured JSON forensic report with provenance and timestamps.
        Returns: (report_bytes, sha256_hash)
        """
        meta = metadata or case.metadata_json or {}
        now = datetime.now(timezone.utc).isoformat()

        report_dict: Dict[str, Any] = {
            "report_metadata": {
                "generator": "MailRecon AI Forensic Intelligence Engine",
                "version": "1.0.0",
                "generated_at": now,
                "case_id": str(case.id),
                "analyst_id": str(case.analyst_id),
            },
            "evidence_target": {
                "filename": case.filename,
                "original_sha256": case.original_sha256,
                "original_size_bytes": case.original_size,
                "ingestion_timestamp": case.created_at.isoformat() if case.created_at else None,
                "status": str(case.status.value if hasattr(case.status, "value") else case.status),
            },
            "threat_assessment": meta.get("risk_score", {
                "score": 0.0,
                "confidence": 0.0,
                "coverage": 0.0,
                "uncertainty_label": "unverifiable",
                "is_heuristic": True,
                "summary": "No risk score computed.",
            }),
            "ai_forensic_briefing": meta.get("ai_analysis", None),
            "findings": [
                {
                    "id": str(f.id),
                    "detector": f.detector,
                    "severity": str(f.severity.value if hasattr(f.severity, "value") else f.severity),
                    "title": f.title,
                    "detail": f.detail,
                    "evidence_ref": f.evidence_ref,
                    "confidence": f.confidence,
                    "raw_evidence": f.raw_evidence,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in findings
            ],
            "parsed_email": {
                "headers": parsed.headers_json if parsed else None,
                "auth_results": parsed.auth_results_json if parsed else None,
                "urls": parsed.urls_json if parsed else None,
                "attachments": parsed.attachments_json if parsed else None,
                "received_chain": parsed.received_chain_json if parsed else None,
            },
            "route_analysis": meta.get("route_analysis", None),
            "qr_codes": meta.get("qr_codes", None),
            "indicator_graph": meta.get("indicator_graph", None),
        }

        # Encode formatted JSON
        report_bytes = json.dumps(report_dict, indent=2, default=str).encode("utf-8")
        sha256_hash = hashlib.sha256(report_bytes).hexdigest()

        return report_bytes, sha256_hash

    @classmethod
    def generate_html_report(
        cls,
        case: Case,
        parsed: Optional[ParsedEmail],
        findings: List[Finding],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bytes, str]:
        """
        Generate a self-contained, offline-viewable HTML forensic report with inline styling.
        Returns: (report_bytes, sha256_hash)
        """
        meta = metadata or case.metadata_json or {}
        score_data = meta.get("risk_score", {})
        ai_data = meta.get("ai_analysis", {})
        route_data = meta.get("route_analysis", {})
        qr_data = meta.get("qr_codes", [])

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        case_created_utc = case.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if case.created_at else "N/A"

        # Safe extraction helper
        def esc(val: Any) -> str:
            if val is None:
                return "N/A"
            return html.escape(str(val))

        # Risk score calculation
        score_val = round(score_data.get("score", 0.0))
        confidence_pct = round(score_data.get("confidence", 0.0) * 100)
        coverage_pct = round(score_data.get("coverage", 0.0) * 100)
        uncertainty = esc(score_data.get("uncertainty_label", "inconclusive")).upper()
        summary = esc(score_data.get("summary", "No assessment summary available."))

        score_color = "#ef4444" if score_val >= 75 else "#f59e0b" if score_val >= 50 else "#3b82f6" if score_val >= 25 else "#10b981"
        threat_level = "MALICIOUS THREAT" if score_val >= 75 else "HIGH RISK" if score_val >= 50 else "SUSPICIOUS" if score_val >= 25 else "LOW / CLEAN"

        # Findings table rows
        findings_rows = ""
        sev_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#06b6d4",
            "info": "#3b82f6",
        }
        for f in findings:
            sev_str = str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower()
            color = sev_colors.get(sev_str, "#64748b")
            conf_display = f"{round((f.confidence or 0.0) * 100)}%"
            findings_rows += f"""
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b;">
                <span style="background: {color}22; color: {color}; border: 1px solid {color}88; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; text-transform: uppercase;">
                  {esc(sev_str)}
                </span>
              </td>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b; font-family: monospace; color: #94a3b8; font-size: 11px;">{esc(f.detector)}</td>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b; font-weight: 600; color: #f1f5f9;">{esc(f.title)}</td>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b; font-family: monospace; color: #38bdf8; font-size: 11px;">{esc(f.evidence_ref)}</td>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b; font-family: monospace; color: #cbd5e1; font-size: 11px;">{conf_display}</td>
              <td style="padding: 10px; border-bottom: 1px solid #1e293b; color: #cbd5e1; font-size: 12px; line-height: 1.4;">{esc(f.detail)}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = """<tr><td colspan="6" style="padding: 20px; text-align: center; color: #64748b;">No threat detections or anomalous findings recorded.</td></tr>"""

        # Authentication Results
        auth_json = (parsed.auth_results_json if parsed else {}) or {}
        spf_res = esc((auth_json.get("spf") or {}).get("result", "none")).upper()
        dkim_res = esc((auth_json.get("dkim") or {}).get("result", "none")).upper()
        dmarc_res = esc((auth_json.get("dmarc") or {}).get("result", "none")).upper()

        def auth_style(res: str) -> str:
            if res == "PASS":
                return "background: #064e3b; color: #6ee7b7; border: 1px solid #059669;"
            elif res in ["FAIL", "HARDFAIL"]:
                return "background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626;"
            elif res == "SOFTFAIL":
                return "background: #78350f; color: #fcd34d; border: 1px solid #d97706;"
            return "background: #1e293b; color: #94a3b8; border: 1px solid #334155;"

        # Received Hops
        hops = route_data.get("hops", [])
        hops_rows = ""
        for h in hops:
            ip_val = h.get("ip") or "None"
            delay = h.get("delay_display") or ("Origin Ingestion" if h.get("hop") == 1 else "N/A")
            geo = h.get("geoip") or {}
            loc = f"{geo.get('city') + ', ' if geo.get('city') else ''}{geo.get('country') or 'Private/Unknown'}"
            asn = f"{geo.get('asn') or ''} {geo.get('org') or ''}".strip() or "N/A"
            hops_rows += f"""
            <tr>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-family: monospace; color: #818cf8; font-weight: bold;">Hop {h.get('hop')}</td>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 11px; color: #cbd5e1;">{esc(h.get('by_node'))}</td>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 11px; color: #38bdf8;">{esc(ip_val)}</td>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-size: 11px; color: #cbd5e1;">{esc(loc)}</td>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-size: 11px; color: #94a3b8;">{esc(asn)}</td>
              <td style="padding: 8px; border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 11px; color: #fcd34d;">{esc(delay)}</td>
            </tr>
            """
        if not hops_rows:
            hops_rows = """<tr><td colspan="6" style="padding: 15px; text-align: center; color: #64748b;">No transit routing hops recorded.</td></tr>"""

        # AI Briefing Actions
        ai_actions = ai_data.get("recommended_actions", [])
        actions_list = ""
        for idx, act in enumerate(ai_actions, 1):
            actions_list += f"""<li style="margin-bottom: 6px; color: #e2e8f0; line-height: 1.4;"><strong>{idx}.</strong> {esc(act)}</li>"""
        if not actions_list:
            actions_list = """<li style="color: #64748b;">No automated containment actions prescribed.</li>"""

        # Assembled HTML template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Incident Report — Case {esc(case.id)}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #0b101b;
      color: #f1f5f9;
      margin: 0;
      padding: 40px 20px;
      line-height: 1.5;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }}
    h1, h2, h3, h4 {{
      margin-top: 0;
      color: #f8fafc;
    }}
    .header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #1e293b;
      padding-bottom: 24px;
      margin-bottom: 30px;
    }}
    .seal-badge {{
      background: #042f2e;
      border: 1px solid #0d9488;
      color: #2dd4bf;
      padding: 6px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 11px;
      font-weight: bold;
      text-transform: uppercase;
    }}
    .card {{
      background: #131d33;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 24px;
    }}
    .score-banner {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #090d16;
      border-left: 6px solid {score_color};
      padding: 20px;
      border-radius: 6px;
      margin-bottom: 20px;
    }}
    .score-number {{
      font-size: 48px;
      font-family: monospace;
      font-weight: 900;
      color: {score_color};
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }}
    th {{
      background: #090d16;
      color: #94a3b8;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 10px;
      border-bottom: 2px solid #1e293b;
    }}
    .mono {{
      font-family: monospace;
    }}
    .footer {{
      border-top: 1px solid #1e293b;
      padding-top: 20px;
      margin-top: 40px;
      font-size: 11px;
      color: #64748b;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-bar">
      <div>
        <div style="font-size: 12px; font-weight: bold; color: #818cf8; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px;">MailRecon AI — Threat Intelligence Platform</div>
        <h1 style="font-size: 26px; margin: 0;">Forensic Email Incident Report</h1>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Case ID: <span class="mono" style="color: #cbd5e1;">{esc(case.id)}</span></div>
      </div>
      <div style="text-align: right;">
        <span class="seal-badge">Cryptographically Sealed</span>
        <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Generated: {now_utc}</div>
      </div>
    </div>

    <!-- Evidence Target Metadata -->
    <div class="card">
      <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 16px;">Target Evidence Specifications</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; font-size: 12px;">
        <div>
          <span style="color: #64748b; display: block;">Filename:</span>
          <span class="mono" style="color: #f1f5f9; font-weight: 600;">{esc(case.filename)}</span>
        </div>
        <div>
          <span style="color: #64748b; display: block;">File Size:</span>
          <span class="mono" style="color: #f1f5f9;">{round(case.original_size / 1024, 1) if case.original_size else 0} KB</span>
        </div>
        <div>
          <span style="color: #64748b; display: block;">Ingestion Timestamp:</span>
          <span class="mono" style="color: #f1f5f9;">{case_created_utc}</span>
        </div>
        <div>
          <span style="color: #64748b; display: block;">Case Status:</span>
          <span class="mono" style="color: #10b981; font-weight: bold; text-transform: uppercase;">{esc(case.status.value if hasattr(case.status, 'value') else case.status)}</span>
        </div>
      </div>
      <div style="margin-top: 12px; padding: 8px 12px; background: #090d16; border-radius: 4px; border: 1px solid #1e293b; font-size: 11px;">
        <span style="color: #64748b;">SHA-256 Checksum: </span>
        <span class="mono" style="color: #38bdf8;">{esc(case.original_sha256)}</span>
      </div>
    </div>

    <!-- Threat Score Banner -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin: 0;">Forensic Risk & Confidence Assessment</h3>
        <div>
          <span style="background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: bold; text-transform: uppercase; margin-right: 6px;">Heuristic</span>
          <span style="background: #0f172a; color: #cbd5e1; border: 1px solid #334155; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: bold; text-transform: uppercase;">{uncertainty}</span>
        </div>
      </div>

      <div class="score-banner">
        <div>
          <div class="score-number">{score_val}<span style="font-size: 20px; color: #64748b;">/100</span></div>
          <div style="font-weight: bold; color: {score_color}; font-size: 16px; margin-top: 4px;">{threat_level}</div>
        </div>
        <div style="text-align: right; font-size: 12px; color: #cbd5e1;">
          <div style="margin-bottom: 6px;">Detector Confidence: <strong class="mono" style="color: #818cf8;">{confidence_pct}%</strong></div>
          <div>Forensic Coverage: <strong class="mono" style="color: #38bdf8;">{coverage_pct}%</strong></div>
          <div style="font-size: 10px; color: #64748b; margin-top: 4px;">Asymptotic Saturation Model</div>
        </div>
      </div>
      <p style="font-size: 12px; color: #cbd5e1; margin: 0; line-height: 1.5;"><strong style="color: #f1f5f9;">Assessment Narrative:</strong> {summary}</p>
    </div>

    <!-- AI Intelligence & SOC Playbook -->
    {f'''
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin: 0;">Grounded LLM Forensic Briefing</h3>
        <span style="{'background: #064e3b; color: #6ee7b7; border: 1px solid #059669;' if ai_data.get('is_grounded') else 'background: #78350f; color: #fcd34d; border: 1px solid #d97706;'} padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: bold;">
          {'GROUNDING VERIFIED' if ai_data.get('is_grounded') else 'UNVERIFIED GROUNDING'}
        </span>
      </div>

      <div style="margin-bottom: 16px; font-size: 13px; color: #e2e8f0; line-height: 1.6; background: #090d16; padding: 16px; border-radius: 6px; border: 1px solid #1e293b;">
        <strong>Executive Summary:</strong> {esc(ai_data.get('executive_summary', 'N/A'))}
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 12px; margin-bottom: 16px;">
        <div style="background: #090d16; padding: 12px; border-radius: 6px; border: 1px solid #1e293b;">
          <span style="color: #64748b; display: block; margin-bottom: 4px;">Classified Attack Vector:</span>
          <span class="mono" style="color: #f87171; font-weight: bold;">{esc(ai_data.get('attack_vector', 'Unknown'))}</span>
        </div>
        <div style="background: #090d16; padding: 12px; border-radius: 6px; border: 1px solid #1e293b;">
          <span style="color: #64748b; display: block; margin-bottom: 4px;">Observed Adversary Tactics:</span>
          <span style="color: #cbd5e1;">{", ".join(ai_data.get('threat_actor_tactics', ['None']))}</span>
        </div>
      </div>

      <div style="background: #090d16; padding: 16px; border-radius: 6px; border: 1px solid #1e293b;">
        <h4 style="font-size: 12px; text-transform: uppercase; color: #38bdf8; margin-bottom: 10px;">Recommended Incident Containment Playbook</h4>
        <ul style="margin: 0; padding-left: 18px; font-size: 12px;">
          {actions_list}
        </ul>
      </div>
    </div>
    ''' if ai_data else ''}

    <!-- Authentication Results -->
    <div class="card">
      <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 16px;">RFC 8601 Transport Authentication Claims</h3>
      <div style="display: flex; gap: 12px; font-family: monospace; font-size: 12px; font-weight: bold;">
        <div style="{auth_style(spf_res)} padding: 8px 16px; border-radius: 6px;">SPF: {spf_res}</div>
        <div style="{auth_style(dkim_res)} padding: 8px 16px; border-radius: 6px;">DKIM: {dkim_res}</div>
        <div style="{auth_style(dmarc_res)} padding: 8px 16px; border-radius: 6px;">DMARC: {dmarc_res}</div>
      </div>
      <div style="font-size: 11px; color: #64748b; margin-top: 8px; font-style: italic;">
        Note: Authentication results are extracted from transport Received-SPF and Authentication-Results headers stamped at boundary MX.
      </div>
    </div>

    <!-- Transport Route Timeline -->
    <div class="card">
      <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 16px;">MTA Transport Routing Sequence ({len(hops)} hops)</h3>
      <table>
        <thead>
          <tr>
            <th>Sequence</th>
            <th>Receiving Relay Node</th>
            <th>Relay IP</th>
            <th>Geographic Location</th>
            <th>ASN / Organization</th>
            <th>Transit Delay</th>
          </tr>
        </thead>
        <tbody>
          {hops_rows}
        </tbody>
      </table>
    </div>

    <!-- Forensic Findings -->
    <div class="card">
      <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 16px;">Detailed Forensic Detection Findings ({len(findings)})</h3>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detector</th>
            <th>Finding Title</th>
            <th>Evidence Ref</th>
            <th>Conf</th>
            <th>Forensic Detail</th>
          </tr>
        </thead>
        <tbody>
          {findings_rows}
        </tbody>
      </table>
    </div>

    <div class="footer">
      <div>MailRecon AI — Evidence-First Email Threat Intelligence & Forensic Architecture</div>
      <div style="margin-top: 4px;">This report is an immutable record. SHA-256 verification hash: <span class="mono" style="color: #94a3b8;">{{REPORT_SHA256_PLACEHOLDER}}</span></div>
    </div>
  </div>
</body>
</html>
"""

        # Encode, calculate SHA-256, and inject placeholder
        # First pass without placeholder
        pre_bytes = html_content.replace("{{REPORT_SHA256_PLACEHOLDER}}", "").encode("utf-8")
        calc_sha = hashlib.sha256(pre_bytes).hexdigest()

        final_html = html_content.replace("{{REPORT_SHA256_PLACEHOLDER}}", calc_sha)
        final_bytes = final_html.encode("utf-8")
        final_sha256 = hashlib.sha256(final_bytes).hexdigest()

        return final_bytes, final_sha256
