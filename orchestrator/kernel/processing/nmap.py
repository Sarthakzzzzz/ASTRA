import xml.etree.ElementTree as ET
from typing import List, Optional
from orchestrator.kernel.finding_models import StandardFinding

def parse_nmap_xml(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nmap XML output and emits atomic facts with proven capabilities.
    Only emit capability when scanner provides evidence.
    """
    findings = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        target = target_context or root.find('.//address').get('addr', 'unknown') if root.find('.//address') is not None else 'unknown'

        for host in root.findall('host'):
            ip = host.find('address').get('addr') if host.find('address') is not None else target
            
            # Extract OS details if available
            os_element = host.find('.//osclass')
            os_family = os_element.get('osfamily', '').lower() if os_element is not None else None
            
            for port in host.findall('.//port'):
                state = port.find('state').get('state') if port.find('state') is not None else ""
                
                if state == 'open':
                    port_id = int(port.get('portid', 0))
                    service_elem = port.find('service')
                    
                    service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                    product = service_elem.get('product', '') if service_elem is not None else ''
                    version = service_elem.get('version', '') if service_elem is not None else ''

                    port_desc = f"{service} ({product} {version})" if product else service

                    finding = StandardFinding(
                        id=f"nmap_port_{ip}_{port_id}",
                        source_tool="nmap",
                        finding_type="open_port",
                        target=ip,
                        finding_value=str(port_id),
                        port=port_id,
                        service=service.lower(),
                        os=os_family,
                        version=version if version else None,
                        details={
                            "protocol": port.get('protocol', 'tcp'),
                            "product": product,
                            "original_desc": port_desc
                        },
                        risk_level="enum" # Nmap open ports are reconnaissance facts
                    )
                    
                    # CAPABILITY INFERENCE: 
                    # If this port provides a clear capability, tag it.
                    if port_id in [21, 22, 23, 3389, 5900]:
                        finding.capability = "remote_access_service"
                        finding.finding_type = "service"
                        
                    elif port_id in [80, 443, 8080, 8443]:
                        finding.capability = "web_service"
                        finding.finding_type = "web_service"
                    
                    elif port_id in [1433, 3306, 5432, 1521, 27017, 6379]:
                        finding.capability = "database_service"
                        finding.finding_type = "service"

                    # Parse Nmap scripts (like vulners) which might be attached to this port
                    for script in port.findall('script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        
                        if script_id == 'vulners':
                            # Nmap vulners script attaches CVE IDs
                            finding.risk_level = "exploit"
                            finding.finding_type = "vulnerability"
                            finding.details["vulners_output"] = output
                            # Extract CVEs from text
                            cves = [word for word in output.split() if "CVE-" in word]
                            if cves:
                                finding.details["cves"] = cves

                    findings.append(finding)
                    
    except ET.ParseError as e:
        print(f"Error parsing Nmap XML {file_path}: {e}")
    except Exception as e:
        print(f"Unexpected error parsing Nmap XML {file_path}: {e}")
        
    return findings
