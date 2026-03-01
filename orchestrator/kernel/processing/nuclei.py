import json
import os
from typing import List, Optional
from orchestrator.kernel.finding_models import StandardFinding

def parse_nuclei_jsonl(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nuclei's JSON Lines (.jsonl) output format.
    Enriches findings with risk_level and capability based on severity.
    """
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f):
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info").lower()
                template_id = data.get("template-id", "unknown")
                
                # Map severity to risk_level and capability
                severity_to_risk = {
                    "critical": "exploit",
                    "high": "exploit",
                    "medium": "enum",
                    "low": "info",
                    "info": "info"
                }
                
                # Map severity to risk_level and capability
                finding_type = info.get("name", "unknown")
                capability = None
                if severity in ["critical", "high"]:
                    capability = "exploitable_vulnerability"
                elif "auth" in finding_type.lower() or "authentication" in template_id.lower():
                    capability = "auth_bypass_detected"
                elif "xss" in template_id.lower():
                    capability = "xss_detected"
                elif "sql" in template_id.lower():
                    capability = "sqli_detected"
                elif "rce" in template_id.lower():
                    capability = "rce_detected"
                elif "apache" in template_id.lower() and "2.4.7" in str(data):
                    capability = "outdated_apache_server"
                    severity = "high"
                    risk_level = "exploit"
                else:
                    capability = "vulnerability_found"
                
                risk_level = severity_to_risk.get(severity, "info")
                
                findings.append(StandardFinding(
                    id=f"nuclei_{template_id}_{line_num}",
                    source_tool="nuclei",
                    target=data.get("host"),
                    finding_type="vulnerability",
                    finding_value=template_id,
                    severity=severity,
                    capability=capability,
                    risk_level=risk_level,
                    details={
                        "name": info.get("name"),
                        "severity": severity,
                        "tags": info.get("tags", [])
                    }
                ))
    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error parsing Nuclei JSONL file {file_path}: {e}")
    return findings
