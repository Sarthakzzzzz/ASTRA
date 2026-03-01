import os
import json
import xml.etree.ElementTree as ET
import nvdlib
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from langchain_tavily import TavilySearch
from langchain_core.tools import tool

# Load environment variables
load_dotenv()

class ResearchAgentExtractor:
    def __init__(self, tavily_api_key: Optional[str] = None):
        self.tavily_api_key = tavily_api_key or os.getenv("TAVILY_API_KEY")
        if self.tavily_api_key:
            os.environ["TAVILY_API_KEY"] = self.tavily_api_key
        
        try:
            self.tavily_tool = TavilySearch(max_results=3) if self.tavily_api_key else None
        except Exception:
            self.tavily_tool = None

    def parse_nuclei_results(self, file_path: str) -> List[Dict[str, Any]]:
        """Parses Nuclei .jsonl output for CVEs and findings."""
        findings = []
        if not os.path.exists(file_path):
            return findings
        
        with open(file_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    finding = {
                        "target": data.get("host"),
                        "template_id": data.get("template-id"),
                        "name": info.get("name"),
                        "severity": info.get("severity"),
                        "description": info.get("description"),
                        "cves": info.get("classification", {}).get("cve-id", []),
                        "type": "vulnerability"
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
        return findings

    def parse_nmap_results(self, file_path: str) -> List[Dict[str, Any]]:
        """Parses Nmap .xml output for services and versions."""
        findings = []
        if not os.path.exists(file_path):
            return findings
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                addr = host.find("address").get("addr")
                for port in host.findall("ports/port"):
                    portid = port.get("portid")
                    service = port.find("service")
                    if service is not None:
                        finding = {
                            "target": addr,
                            "port": portid,
                            "service": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "type": "service"
                        }
                        findings.append(finding)
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            
        return findings

    @tool
    def get_nvd_details(cve_id: str) -> Dict[str, Any]:
        """Queries NVD for detailed CVE information including CVSS and description."""
        try:
            api_key = os.getenv("NVD_API_KEY")
            # Passing key to searchCVE for higher rate limits
            r = nvdlib.searchCVE(cveId=cve_id, key=api_key)[0]
            # Handle different CVSS versions
            cvss_score = None
            severity = "UNKNOWN"
            
            if hasattr(r, 'v31score'):
                cvss_score = r.v31score
                severity = r.v31severity
            elif hasattr(r, 'v30score'):
                cvss_score = r.v30score
                severity = r.v30severity
            elif hasattr(r, 'v2score'):
                cvss_score = r.v2score
                severity = r.v2severity

            return {
                "cve_id": cve_id,
                "description": r.descriptions[0].value if r.descriptions else "No description",
                "cvss_score": cvss_score,
                "severity": severity,
                "last_modified": r.lastModified
            }
        except Exception as e:
            return {"error": f"Failed to fetch NVD data for {cve_id}: {str(e)}"}

    @tool
    def get_exploit_context(query: str) -> str:
        """Searches Tavily for real-world exploit context or PoCs for a vulnerability."""
        # This is a wrapper around TavilySearchResults for specific exploit hunting
        # In a real multi-agent setup, this would be invoked by the Research Agent
        try:
            # Instantiate with a dummy key if missing to avoid Pydantic validation errors during dry runs/tests
            # though mocking is preferred, this adds a layer of safety.
            api_key = os.getenv("TAVILY_API_KEY")
            if not api_key:
                return "Search failed: TAVILY_API_KEY not found in environment."
                
            search = TavilySearch(max_results=3)
            results = search.run(f"exploit PoC for {query}")
            return str(results)
        except Exception as e:
            return f"Search failed: {str(e)}"

