import pytest
from unittest.mock import patch, MagicMock
from langchain_core.documents import Document

from rag.attack_path_agent.retriever import AttackPathRetriever
from rag.attack_path_agent.prompt_builder import AttackPathPromptBuilder
from rag.attack_path_agent.generator import AttackPathGenerator

@pytest.fixture
def mock_retriever():
    # AttackPathRetriever now delegates to ContextRetriever.retrieve_all.
    # Patch that method so we control what comes back without needing real DBs.
    mock_doc = Document(
        page_content="CVE-2021-44228: Critical RCE in Log4j.",
        metadata={"primary_cve": "CVE-2021-44228", "target": "10.0.0.1",
                  "severity": "critical", "finding_type": "vulnerability"}
    )
    mock_neo4j_path = {"path": "(Asset {ip: '10.0.0.1'})-[:EXPOSES]->(Port {port_id: '80'})"}

    from rag.research_agent.phase3_retrieval.retrieval_result import RetrievalResult, RankedFinding
    mock_result = RetrievalResult(
        target_identifier="10.0.0.1",
        ranked_findings=[
            RankedFinding(
                target="10.0.0.1", name="Log4Shell", finding_type="vulnerability",
                severity="critical", primary_cve="CVE-2021-44228",
                description="Critical RCE in Log4j.", cvss_score=10.0, exploit_context=None
            )
        ],
        semantic_docs=[mock_doc],
        structural_paths=[mock_neo4j_path],
        retrieval_errors=[],
    )

    with patch(
        "rag.attack_path_agent.retriever.ContextRetriever.retrieve_all",
        return_value=mock_result
    ):
        retriever = AttackPathRetriever()
        yield retriever


def test_retriever_context_assembly(mock_retriever):
    context = mock_retriever.retrieve_context("10.0.0.1")

    assert "semantic_context" in context
    assert "structural_paths" in context

    # Semantic docs still present
    assert len(context["semantic_context"]) == 1
    assert "Log4j" in context["semantic_context"][0].page_content

    # Structural paths still present
    assert len(context["structural_paths"]) == 1
    assert "10.0.0.1" in str(context["structural_paths"][0])

    # New: ranked findings are also available
    assert "ranked_findings" in context
    assert context["ranked_findings"][0].primary_cve == "CVE-2021-44228"

def test_prompt_builder_synthesis():
    builder = AttackPathPromptBuilder()
    
    context = {
        "semantic_context": [
            Document(page_content="A severe vulnerability.", metadata={"primary_cve": "CVE-1234"})
        ],
        "structural_paths": [
            {"path": "NodeA -> NodeB"}
        ]
    }
    
    prompt = builder.build_prompt("192.168.1.5", context)
    
    # Verify persona is set
    assert "Expert Red Teamer" in prompt
    # Verify strict DOT format instruction
    assert "strict Graphviz DOT format" in prompt
    # Verify structural data injection
    assert "NodeA -> NodeB" in prompt
    # Verify semantic context injection
    assert "A severe vulnerability." in prompt
    assert "CVE-1234" in prompt

@patch("rag.attack_path_agent.generator.ChatGoogleGenerativeAI")
@patch.dict("os.environ", {"GOOGLE_API_KEY": "fake_key"})
def test_generator_streaming(mock_gemini):
    # Mock the language model stream
    mock_llm_instance = MagicMock()
    
    # Create fake chunks
    chunk1 = MagicMock()
    chunk1.content = "digraph AttackPath {\n"
    chunk2 = MagicMock()
    chunk2.content = '  "10.0.0.1" -> "Port 80";\n'
    chunk3 = MagicMock()
    chunk3.content = "}"
    
    mock_llm_instance.stream.return_value = [chunk1, chunk2, chunk3]
    mock_gemini.return_value = mock_llm_instance
    
    # Mock the GraphStore so we don't try to connect to a real Neo4j
    mock_graph_store = MagicMock()
    
    generator = AttackPathGenerator(graph_store=mock_graph_store)
    
    stream_output = list(generator.generate_stream("Create a map", target_identifier="10.0.0.1"))
    
    assert len(stream_output) == 3
    assert "digraph AttackPath" in stream_output[0]
    assert "Port 80" in stream_output[1]
    
    # Verify it called the underlying LLM stream method
    mock_llm_instance.stream.assert_called_once()
    
    # Verify that the full response was saved to Neo4j
    expected_full_response = "digraph AttackPath {\n  \"10.0.0.1\" -> \"Port 80\";\n}"
    mock_graph_store.graph.query.assert_called_once()
    args, kwargs = mock_graph_store.graph.query.call_args
    assert "MERGE (ap:AttackPath" in args[0]
    assert kwargs["params"]["target"] == "10.0.0.1"
    assert kwargs["params"]["dot_content"] == expected_full_response
