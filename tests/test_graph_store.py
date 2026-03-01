import pytest
from unittest.mock import patch, MagicMock
from rag.research_agent.phase2_database.graph_store import AttackGraphStore

@pytest.fixture
def mock_neo4j():
    with patch("rag.research_agent.phase2_database.graph_store.Neo4jGraph") as mock:
        yield mock

def test_graph_store_initialization(mock_neo4j):
    # Test successful init
    store = AttackGraphStore()
    assert store.graph is not None
    mock_neo4j.assert_called_once()

@patch("rag.research_agent.phase2_database.graph_store.Neo4jGraph")
def test_graph_store_failed_init(mock_neo4j):
    # Test failed init (e.g. Neo4j not running)
    mock_neo4j.side_effect = Exception("Connection Refused")
    store = AttackGraphStore()
    assert store.graph is None

def test_ingest_service_finding(mock_neo4j):
    mock_graph_instance = MagicMock()
    mock_neo4j.return_value = mock_graph_instance
    
    store = AttackGraphStore()
    
    finding = {
        "type": "service",
        "target": "10.0.0.1",
        "port": "80",
        "service": "http",
        "product": "Apache",
        "version": "2.4"
    }
    
    store.ingest_findings([finding])
    
    # Check that query was called twice (once for Asset MERGE, once for Service relationships)
    assert mock_graph_instance.query.call_count == 2
    
    # Verify the parameters passed to the second query (the service map query)
    args, kwargs = mock_graph_instance.query.call_args_list[1]
    params = kwargs.get("params", {})
    assert params["ip"] == "10.0.0.1"
    assert params["port"] == "80"
    assert params["service"] == "http"

def test_ingest_vulnerability_finding(mock_neo4j):
    mock_graph_instance = MagicMock()
    mock_neo4j.return_value = mock_graph_instance
    
    store = AttackGraphStore()
    
    finding = {
        "type": "vulnerability",
        "target": "192.168.1.100",
        "name": "SQL Injection",
        "cves": ["CVE-2023-1234"],
        "severity": "high"
    }
    
    store.ingest_findings([finding])
    
    # Assert query called twice (Asset MERGE, Vuln mapping)
    assert mock_graph_instance.query.call_count == 2
    
    args, kwargs = mock_graph_instance.query.call_args_list[1]
    params = kwargs.get("params", {})
    assert params["ip"] == "192.168.1.100"
    assert params["name"] == "SQL Injection"
    assert params["cve"] == "CVE-2023-1234"
