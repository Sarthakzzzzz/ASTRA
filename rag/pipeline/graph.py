from langgraph.graph import StateGraph, END
from rag.pipeline.state import GraphState
from rag.pipeline.nodes import recommendation_node, rag_enrichment_node, attack_path_node

def build_workflow(checkpointer=None, interrupt_before=None) -> StateGraph:
    """
    Constructs the linear Multi-Agent RAG workflow using LangGraph.
    Flow: Start -> RAG Enrichment -> Recommendation -> Attack Path -> End
    """
    workflow = StateGraph(GraphState)

    # 1. Add Nodes
    workflow.add_node("rag_enrichment", rag_enrichment_node)
    workflow.add_node("recommendation", recommendation_node)
    workflow.add_node("attack_path", attack_path_node)

    # 2. Add Edges (Linear flow)
    workflow.set_entry_point("rag_enrichment")
    workflow.add_edge("rag_enrichment", "recommendation")
    workflow.add_edge("recommendation", "attack_path")
    workflow.add_edge("attack_path", END)

    # 3. Compile
    return workflow.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
