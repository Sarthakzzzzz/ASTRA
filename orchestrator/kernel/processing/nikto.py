import json
from typing import List, Optional
from orchestrator.kernel.finding_models import StandardFinding
from orchestrator.kernel.rule_interpreter import load_rules, match_rules_to_findings

def parse_nikto_txt(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nikto text output and emits findings with appropriate risk levels.
    Nikto identifies web server misconfigurations and vulnerabilities.
    """
    findings = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
            if not content.strip():
                return findings
                
            # Extract basic target info if possible
            target_ip = target_context
            for line in content.split('\n'):
                if line.startswith('+ Target IP:'):
                    target_ip = line.split(':', 1)[1].strip()
                    break
                    
            if not target_ip:
                target_ip = "unknown"
                
            # Parse individual findings (lines starting with + that aren't headers)
            header_prefixes = ['+ Target', '+ Start Time', '+ Scan completed', '-----------------', '+ Server:', '+ Retrieved']
            
            for line_idx, line in enumerate(content.split('\n')):
                line = line.strip()
                if not line.startswith('+'):
                    continue
                    
                is_header = any(line.startswith(prefix) for prefix in header_prefixes)
                if is_header:
                    continue
                
                # It's a finding
                finding_text = line[1:].strip()
                
                # Check for OSVDB or CVE references to determine severity
                is_vuln = 'OSVDB-' in finding_text or 'CVE-' in finding_text
                
                finding = StandardFinding(
                    id=f"nikto_{target_ip}_{line_idx}",
                    source_tool="nikto",
                    finding_type="vulnerability" if is_vuln else "misconfiguration",
                    target=target_ip,
                    finding_value=finding_text,
                    severity="HIGH" if is_vuln else "INFO",
                    details={
                        "raw_output": finding_text,
                    }
                )
                
                if is_vuln:
                    finding.risk_level = "exploit"
                    finding.capability = "vulnerable_web_component"
                elif 'directory found' in finding_text.lower():
                    finding.risk_level = "enum"
                    finding.capability = "information_disclosure"
                    finding.finding_type = "directory_exposure"
                else:
                    finding.risk_level = "info"
                    finding.capability = "misconfiguration"
                    
                findings.append(finding)
                
    except FileNotFoundError:
         print(f"Nikto output file not found: {file_path}")
    except Exception as e:
        print(f"Unexpected error parsing Nikto output {file_path}: {e}")
        
    # Optional: Apply rules engine to automatically upgrade risks
    # only if rules exist and risk is high
    try:
        rules = load_rules()
        if rules:
            matched_rules = match_rules_to_findings(findings, rules)
            for rule_match in matched_rules:
                for f in findings:
                    if getattr(f, 'id', '') == rule_match.get('finding_id'):
                        f.risk_level = "exploit" # Rule matched, upgrade to exploit
                        f.details['matched_rule'] = rule_match.get('rule_name')
    except Exception as e:
         print(f"Failed to apply rules to nikto findings: {e}")
         
    return findings
