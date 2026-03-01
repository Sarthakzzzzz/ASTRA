import pytest
from unittest.mock import patch
from rag.workflow.graph import build_workflow
from rag.workflow.state import GraphState

@pytest.fixture
def mock_workflow_dependencies():
    """
    Mocks out all the heavy external dependencies (LLMs, Databases, APIs)
    to ensure we are purely testing the LangGraph execution flow.
    """
    with patch("rag.workflow.nodes.analyze_dynamic_scan") as MockAnalyzeDynamicScan, \
         patch("rag.workflow.nodes.ResearchAgentExtractor") as MockExtractor, \
         patch("rag.workflow.nodes.DocumentProcessor") as MockDocProcessor, \
         patch("rag.workflow.nodes.VulnerabilityVectorStore") as MockVectorStore, \
         patch("rag.workflow.nodes.AttackGraphStore") as MockGraphStore, \
         patch("rag.workflow.nodes.AttackPathRetriever") as MockRetriever, \
         patch("rag.workflow.nodes.AttackPathPromptBuilder") as MockPromptBuilder, \
         patch("rag.workflow.nodes.AttackPathGenerator") as MockGenerator:
        
        # 1. Mock Recommendation Output
        MockAnalyzeDynamicScan.return_value = [{"tool": "nmap", "command": "nmap -sV target"}]
        
        # 2. Mock RAG Extraction Output
        mock_extractor_instance = MockExtractor.return_value
        # Assuming .run() returns a dict or string
        mock_extractor_instance.get_nvd_details.run.return_value = {"cvss": 9.8}
        mock_extractor_instance.get_exploit_context.run.return_value = {"pocs": []}
        
        # 3. Mock Attack Path Output
        mock_retriever_instance = MockRetriever.return_value
        mock_retriever_instance.retrieve_context.return_value = {"semantic_context": [], "structural_paths": []}
        
        mock_prompt_builder_instance = MockPromptBuilder.return_value
        mock_prompt_builder_instance.build_prompt.return_value = "Mocked Master Prompt"
        
        mock_generator_instance = MockGenerator.return_value
        mock_generator_instance.generate.return_value = "digraph MockedGraph { A -> B; }"
        
        yield {
            "analyze_dynamic_scan": MockAnalyzeDynamicScan,
            "extractor": MockExtractor,
            "generator": MockGenerator
        }


def test_full_workflow_execution(mock_workflow_dependencies):
    """
    Tests that a state injected into the LangGraph reaches the end
    and accumulates data from all three nodes.
    """
    # 1. Initialize Graph
    workflow = build_workflow()
    
    # 2. Define Initial State
    initial_state = GraphState(
        target_identifier="192.168.1.100",
        scan_findings=[
            {
                "type": "vulnerability",
                "name": "Tomcat Default Credentials",
                "cves": ["CVE-2017-12615"],
                "host": "192.168.1.100",
                "port": 8080
            }
        ],
        recommended_tools=[],
        enriched_rag_data=[],
        attack_path_graph=None,
        error=None
    )
    
    # 3. Execute Graph
    final_state = workflow.invoke(initial_state)
    
    # 4. Assert State Transitions (Recommendation Node)
    assert "recommended_tools" in final_state
    assert len(final_state["recommended_tools"]) == 1
    assert final_state["recommended_tools"][0]["tool"] == "nmap"
    
    # 5. Assert State Transitions (RAG Enrichment Node)
    assert "enriched_rag_data" in final_state
    assert len(final_state["enriched_rag_data"]) == 1
    # Check that NVD/Exploit context was appended
    assert "nvd_details" in final_state["enriched_rag_data"][0]
    assert "exploit_context" in final_state["enriched_rag_data"][0]
    
    # 6. Assert State Transitions (Attack Path Node)
    assert "attack_path_graph" in final_state
    assert final_state["attack_path_graph"] == "digraph MockedGraph { A -> B; }"
    
    # Check for NO workflow errors
    assert final_state.get("error") is None
