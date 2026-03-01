from typing import TypedDict, List, Dict, Any, Optional

class GraphState(TypedDict):
    """
    Represents the state of the LangGraph workflow throughout the ASTRA pipeline.
    """
    target_identifier: str
    scan_findings: List[Dict[str, Any]]
    executed_tools: List[str]
    recommended_tools: List[Dict[str, str]]
    enriched_rag_data: List[Dict[str, Any]]
    attack_path_graph: Optional[str]
    error: Optional[str]
