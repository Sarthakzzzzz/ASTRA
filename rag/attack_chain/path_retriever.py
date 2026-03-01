"""
AttackPathRetriever: delegates to the Phase 3 ContextRetriever.

Previously this class re-implemented its own ChromaDB and Neo4j queries.
Now it acts as a thin adapter that calls phase3_retrieval.ContextRetriever
so the attack path agent automatically benefits from ranking, deduplication,
and severity filtering.
"""
from typing import Any, Dict

from rag.threat_intel.search.semantic_search import ContextRetriever
from rag.threat_intel.search.search_models import RetrievalResult
from rag.threat_intel.database.chroma_store import VulnerabilityVectorStore
from rag.threat_intel.database.neo4j_store import AttackGraphStore


class AttackPathRetriever:
    def __init__(
        self,
        vector_store: VulnerabilityVectorStore = None,
        graph_store: AttackGraphStore = None,
    ):
        """
        Initializes the retriever. Stores are injected for testability;
        if omitted, real connections are created.
        """
        self._context_retriever = ContextRetriever(
            vector_store=vector_store or VulnerabilityVectorStore(),
            graph_store=graph_store   or AttackGraphStore(),
        )

    def retrieve_context(self, target_identifier: str, k: int = 5) -> Dict[str, Any]:
        """
        Retrieves ranked, deduplicated context for a target via Phase 3.
        Returns a dict compatible with AttackPathPromptBuilder.build_prompt():
            {
                "semantic_context":  List[Document],
                "structural_paths":  List[Dict],
                "ranked_findings":   List[RankedFinding],   ← new, for richer prompts
            }
        """
        result: RetrievalResult = self._context_retriever.retrieve_all(
            target=target_identifier,
            k=k,
            severity_filter="medium",
        )

        return {
            "semantic_context":  result.semantic_docs,
            "structural_paths":  result.structural_paths,
            "ranked_findings":   result.ranked_findings,
            "retrieval_errors":  result.retrieval_errors,
        }
