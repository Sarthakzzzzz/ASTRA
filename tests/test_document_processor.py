import pytest
from rag.research_agent.phase2_database.document_processor import DocumentProcessor

@pytest.fixture
def processor():
    return DocumentProcessor()

def test_process_vulnerability_finding(processor):
    finding = {
        "type": "vulnerability",
        "target": "10.0.0.1",
        "name": "Apache Log4j RCE",
        "cves": ["CVE-2021-44228"],
        "severity": "critical",
        "description": "Initial scan desc.",
        "nvd_details": {
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "Detailed NVD description."
        },
        "exploit_context": "Found multiple PoCs online."
    }
    
    docs = processor.process_findings([finding])
    
    assert len(docs) == 1
    doc = docs[0]
    
    # Check Metadata
    assert doc.metadata["target"] == "10.0.0.1"
    assert doc.metadata["finding_type"] == "vulnerability"
    assert doc.metadata["severity"] == "critical"
    assert doc.metadata["primary_cve"] == "CVE-2021-44228"
    
    # Check Content
    assert "Apache Log4j RCE" in doc.page_content
    assert "CVE-2021-44228" in doc.page_content
    assert "Detailed NVD description." in doc.page_content
    assert "Found multiple PoCs online." in doc.page_content

def test_process_service_finding(processor):
    finding = {
        "type": "service",
        "target": "192.168.1.5",
        "port": "22",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "8.2p1 Ubuntu"
    }
    
    docs = processor.process_findings([finding])
    
    assert len(docs) == 1
    doc = docs[0]
    
    # Check Metadata
    assert doc.metadata["target"] == "192.168.1.5"
    assert doc.metadata["finding_type"] == "service"
    assert doc.metadata["port"] == "22"
    assert doc.metadata["service"] == "ssh"
    
    # Check Content
    assert "Service/Port finding" in doc.page_content
    assert "OpenSSH 8.2p1 Ubuntu" in doc.page_content

def test_embedding_generation(processor):
    # This test actually loads the local model and generates an embedding
    # It might take a few seconds on the first run to download the weights (~90MB)
    finding = {
        "type": "vulnerability",
        "target": "localhost",
        "name": "Test Vuln",
        "description": "A very bad bug."
    }
    docs = processor.process_findings([finding])
    
    embeddings = processor.embed_documents(docs)
    
    assert len(embeddings) == 1
    # all-MiniLM-L6-v2 produces 384-dimensional embeddings
    assert len(embeddings[0]) == 384
    # Check it's mostly floats
    assert isinstance(embeddings[0][0], float)
