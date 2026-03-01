import pytest
import os
import json
from unittest.mock import MagicMock, patch
from rag.research_agent.phase1_extraction.rag_extractor import ResearchAgentExtractor

@pytest.fixture
def extractor():
    return ResearchAgentExtractor(tavily_api_key=os.getenv("TAVILY_API_KEY"))

def test_parse_nuclei_results(tmp_path, extractor):
    # Create fake nuclei output
    nuclei_file = tmp_path / "test_nuclei.jsonl"
    fake_data = {
        "host": "127.0.0.1",
        "template-id": "cve-2021-44228",
        "info": {
            "name": "Apache Log4j2 Remote Code Execution",
            "severity": "critical",
            "description": "Log4j2 RCE",
            "classification": {"cve-id": ["CVE-2021-44228"]}
        }
    }
    nuclei_file.write_text(json.dumps(fake_data) + "\n")
    
    findings = extractor.parse_nuclei_results(str(nuclei_file))
    assert len(findings) == 1
    assert findings[0]["target"] == "127.0.0.1"
    assert "CVE-2021-44228" in findings[0]["cves"]

def test_parse_nmap_results(tmp_path, extractor):
    # Create fake nmap output
    nmap_file = tmp_path / "test_nmap.xml"
    nmap_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port portid="80"><service name="http" product="Apache" version="2.4.41"/></port></ports>
</host>
</nmaprun>"""
    nmap_file.write_text(nmap_content)
    
    findings = extractor.parse_nmap_results(str(nmap_file))
    assert len(findings) == 1
    assert findings[0]["target"] == "10.0.0.1"
    assert findings[0]["service"] == "http"
    assert findings[0]["version"] == "2.4.41"

@patch("nvdlib.searchCVE")
def test_get_nvd_details(mock_search, extractor):
    # Mock NVD response
    mock_item = MagicMock()
    mock_item.v31score = 9.8
    mock_item.v31severity = "CRITICAL"
    mock_item.descriptions = [MagicMock(value="Remote Code Execution vulnerability")]
    mock_item.lastModified = "2021-12-10"
    mock_search.return_value = [mock_item]
    
    # We test the tool directly (it's a static/global-ish tool in rag_extractor)
    from rag.research_agent.phase1_extraction.rag_extractor import ResearchAgentExtractor
    details = ResearchAgentExtractor.get_nvd_details.run("CVE-2021-44228")
    
    assert details["cve_id"] == "CVE-2021-44228"
    assert details["cvss_score"] == 9.8
    assert "Remote Code Execution" in details["description"]
    # Verify it was called with the key (even if key is None in some test envs)
    args, kwargs = mock_search.call_args
    assert "key" in kwargs

@patch("rag.research_agent.phase1_extraction.rag_extractor.TavilySearch")
def test_get_exploit_context(mock_tavily_class, extractor):
    # Mock the instance returned by the class constructor
    mock_instance = MagicMock()
    mock_instance.run.return_value = "Found PoC on GitHub: https://github.com/example/poc"
    mock_tavily_class.return_value = mock_instance
    
    # Set a dummy API key in the environment to satisfy the internal check
    with patch.dict(os.environ, {"TAVILY_API_KEY": "fake_key"}):
        from rag.research_agent.phase1_extraction.rag_extractor import ResearchAgentExtractor
        context = ResearchAgentExtractor.get_exploit_context.run("CVE-2021-44228")
    
    assert "GitHub" in context
    mock_instance.run.assert_called_once()
