import json
from typing import List, Optional
from orchestrator.kernel.finding_models import StandardFinding

def parse_whatweb_json(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses WhatWeb's JSON output file.
    The output can be an array of result objects or multiple arrays (from multiple runs).
    The 'target_context' (URL) is used if not provided in the data.
    Enriches findings with risk_level and capability information.
    """
    findings = []
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                print(f"WhatWeb JSON file is empty: {file_path}")
                return findings
                
            content = content.replace("][", "],[")
            if content.startswith("[") and not content.startswith("[["):
                content = f"[{content}]" 
                
            parsed_data = json.loads(content)
            
            if isinstance(parsed_data, list):
                if len(parsed_data) > 0 and isinstance(parsed_data[0], list):
                    flat_data = []
                    for array in parsed_data:
                        flat_data.extend(array)
                    parsed_data = flat_data

            if not isinstance(parsed_data, list):
                print(f"Unexpected JSON structure in {file_path}. Expected a list.")
                return findings
                
            for entry in parsed_data:
                target = entry.get('target', target_context)
                http_status = entry.get('http_status', 0)
                
                plugins = entry.get('plugins', {})
                tech_stack = []
                
                for plugin_name, plugin_data in plugins.items():
                    tech_stack.append(plugin_name)
                    
                finding = StandardFinding(
                    id=f"whatweb_{target}",
                    source_tool="whatweb",
                    finding_type="tech_stack",
                    target=target,
                    finding_value=", ".join(tech_stack),
                    details={
                        "http_status": http_status,
                        "plugins": plugins
                    },
                    risk_level="enum",
                    capability="web_application"
                )
                
                risky_techs = ["WordPress", "Joomla", "Drupal", "phpMyAdmin", "Apache-Struts"]
                if any(t in tech_stack for t in risky_techs):
                    finding.risk_level = "info"
                    finding.capability = "cms_present"
                    
                findings.append(finding)

    except json.JSONDecodeError as e:
        print(f"Error decoding WhatWeb JSON {file_path}: {e}")
    except Exception as e:
        print(f"Unexpected error parsing WhatWeb JSON {file_path}: {e}")
        
    return findings
