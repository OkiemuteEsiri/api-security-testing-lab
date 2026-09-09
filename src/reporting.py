from __future__ import annotations
from models import Endpoint, Finding
from scoring import prioritized_findings, summarize

def render_markdown(endpoints:list[Endpoint], findings:list[Finding])->str:
    s=summarize(findings,len(endpoints)); lines=["# API Security Assessment","","Synthetic metadata assessment; findings are control gaps, not evidence of exploitation.","","## Executive Summary","",f"- Endpoints assessed: **{s['endpoints_assessed']}**",f"- Findings: **{s['findings']}**",f"- High: **{s['high']}**",f"- Medium: **{s['medium']}**",f"- Posture score: **{s['posture_score']}/100**","","## Prioritized Findings","","| Severity | Control | Endpoint | OWASP API |","| --- | --- | --- | --- |"]
    ordered=prioritized_findings(findings,endpoints)
    for f in ordered: lines.append(f"| {f.severity} | {f.control_id} {f.title} | `{f.endpoint}` | {f.owasp_api} |")
    lines.extend(["","## Remediation & Validation",""])
    for f in ordered: lines.extend([f"### {f.control_id} — {f.title}",f"**Endpoint:** `{f.endpoint}`  ",f"**Evidence:** {f.evidence}  ",f"**Remediation:** {f.remediation}  ",f"**Validation:** {f.validation}",""])
    return "\n".join(lines)
