"""
ContextRetriever: the Phase 3 retrieval layer.

Sits between Phase 2 databases (ChromaDB vector store + Neo4j graph store)
and the Attack Path Agent. Provides:

  - retrieve_by_target()    semantic search filtered to a specific target IP
  - retrieve_by_severity()  fetch findings above a severity threshold
  - retrieve_graph_paths()  pull Neo4j attack chain records
  - retrieve_all()          fused call → RetrievalResult with RankedFindings

Results are assembled into typed dataclasses (retrieval_result.py) and
then ranked/deduplicated by ranker.py before being returned.
"""
from typing import Any, Dict, List, Optional

from langchain_core.documents import Document

from rag.threat_intel.database.chroma_store import VulnerabilityVectorStore
from rag.threat_intel.database.neo4j_store import AttackGraphStore
from .search_models import RankedFinding, RetrievalResult
from .result_ranker import Ranker

# Severity filter ordering — only return findings at or above this threshold
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class ContextRetriever:
    """
    Unified retrieval layer for the RAG pipeline.

    Args:
        vector_store: ChromaDB wrapper (injected or auto-created).
        graph_store:  Neo4j wrapper (injected or auto-created).
    """

    def __init__(
        self,
        vector_store: Optional[VulnerabilityVectorStore] = None,
        graph_store: Optional[AttackGraphStore] = None,
    ):
        self.vector_store = vector_store or VulnerabilityVectorStore()
        self.graph_store  = graph_store  or AttackGraphStore()
        self._ranker      = Ranker()

    # Public API

    def retrieve_by_target(self, target: str, k: int = 5) -> List[Document]:
        """
        Semantic similarity search in ChromaDB, filtered to a specific target IP.
        Returns up to k LangChain Document objects.
        """
        query = f"vulnerabilities and services found on {target}"
        try:
            results = self.vector_store.query(query, k=k)
            # Post-filter: only keep docs whose metadata target matches
            return [doc for doc in results if doc.metadata.get("target") == target] or results
        except Exception as e:
            return []

    def retrieve_by_severity(
        self, severity_filter: str = "medium", k: int = 10
    ) -> List[Document]:
        """
        Fetch findings at or above `severity_filter` from ChromaDB.
        Performs a broad query and post-filters on metadata.
        """
        threshold_idx = _SEVERITY_ORDER.index(severity_filter.lower()) if severity_filter.lower() in _SEVERITY_ORDER else 2
        allowed = set(_SEVERITY_ORDER[threshold_idx:])

        try:
            results = self.vector_store.query("vulnerability finding severity", k=k * 3)
            filtered = [
                doc for doc in results
                if doc.metadata.get("severity", "info").lower() in allowed
            ]
            return filtered[:k]
        except Exception as e:
            return []

    def retrieve_graph_paths(self, target: str) -> List[Dict[str, Any]]:
        """
        Query Neo4j for attack chain paths originating from the target asset.
        Returns raw Neo4j records. Returns an empty list (with an error note)
        if Neo4j is unavailable — this is non-fatal.
        """
        if not self.graph_store.graph:
            return [{"error": "Neo4j unavailable — structural paths skipped."}]

        query = """
        MATCH path=(a:Asset {ip: $target})-[:EXPOSES|RUNS|HAS_VULNERABILITY*1..3]->(v:Vulnerability)
        RETURN path
        LIMIT 20
        """
        try:
            return self.graph_store.graph.query(query, params={"target": target})
        except Exception as e:
            return [{"error": str(e)}]

    def retrieve_all(
        self,
        target: str,
        k: int = 5,
        severity_filter: str = "medium",
    ) -> RetrievalResult:
        """
        Fused retrieval: runs all three source queries and assembles a
        RetrievalResult with ranked, deduplicated RankedFinding objects.

        This is the main entry point for the Attack Path Agent.
        """
        errors: List[str] = []

        # 1. Semantic search (target-scoped)
        semantic_docs = self.retrieve_by_target(target, k=k)

        # 2. Severity-filtered docs (broader)
        severity_docs = self.retrieve_by_severity(severity_filter, k=k * 2)

        # Merge — deduplicate by page_content
        seen_content = set()
        merged_docs: List[Document] = []
        for doc in (semantic_docs + severity_docs):
            key = doc.page_content[:120]
            if key not in seen_content:
                seen_content.add(key)
                merged_docs.append(doc)

        # 3. Structural paths from Neo4j
        structural_paths = self.retrieve_graph_paths(target)
        if structural_paths and "error" in structural_paths[0]:
            errors.append(structural_paths[0]["error"])

        # 4. Convert LangChain Documents → RankedFinding dataclasses
        raw_findings = [
            self._doc_to_ranked_finding(doc) for doc in merged_docs
        ]

        # 5. Deduplicate + score via Ranker
        ranked = self._ranker.rank(raw_findings)

        return RetrievalResult(
            target_identifier=target,
            ranked_findings=ranked,
            structural_paths=structural_paths,
            semantic_docs=merged_docs,
            retrieval_errors=errors,
        )

    # Private helpers

    def _doc_to_ranked_finding(self, doc: Document) -> RankedFinding:
        """Converts a ChromaDB Document back into a RankedFinding dataclass."""
        meta = doc.metadata
        # Try to extract CVSS from page_content (format: "NVD CVSS Score: X.X")
        cvss: Optional[float] = None
        for line in doc.page_content.splitlines():
            if "NVD CVSS Score:" in line:
                try:
                    cvss = float(line.split(":")[-1].strip())
                except ValueError:
                    pass

        exploit_context: Optional[str] = None
        ec_marker = "Exploit Context (Web Search):"
        if ec_marker in doc.page_content:
            exploit_context = doc.page_content.split(ec_marker, 1)[-1].strip()

        return RankedFinding(
            target=meta.get("target", "unknown"),
            name=meta.get("name", "Unknown"),
            finding_type=meta.get("finding_type", "unknown"),
            severity=meta.get("severity", "info"),
            primary_cve=meta.get("primary_cve"),
            description=doc.page_content[:500],
            cvss_score=cvss,
            exploit_context=exploit_context,
            raw_metadata=dict(meta),
        )
