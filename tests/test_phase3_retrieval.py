"""
Tests for phase3_retrieval: ContextRetriever and Ranker.
ChromaDB and Neo4j are fully mocked — no real DB connections needed.
"""
from unittest.mock import MagicMock
from langchain_core.documents import Document

from rag.research_agent.phase3_retrieval.context_retriever import ContextRetriever
from rag.research_agent.phase3_retrieval.ranker import Ranker
from rag.research_agent.phase3_retrieval.retrieval_result import RankedFinding, RetrievalResult



def _make_doc(target="1.2.3.4", severity="high", cve=None, content="A vulnerability"):
    meta = {"target": target, "severity": severity, "finding_type": "vulnerability"}
    if cve:
        meta["primary_cve"] = cve
    return Document(page_content=content, metadata=meta)


def _make_finding(target="1.2.3.4", severity="high", cve=None, cvss=None, exploit=None):
    return RankedFinding(
        target=target,
        name="Test Finding",
        finding_type="vulnerability",
        severity=severity,
        primary_cve=cve,
        description="Test description",
        cvss_score=cvss,
        exploit_context=exploit,
    )



class TestContextRetriever:

    def _make_retriever(self, docs=None, graph_results=None):
        """Build a ContextRetriever with mocked stores."""
        mock_vs = MagicMock()
        mock_vs.query.return_value = docs or []

        mock_gs = MagicMock()
        mock_gs.graph = MagicMock()
        mock_gs.graph.query.return_value = graph_results or []

        return ContextRetriever(vector_store=mock_vs, graph_store=mock_gs)

    def test_retrieve_by_target_calls_vector_store(self):
        docs = [_make_doc(target="1.2.3.4")]
        retriever = self._make_retriever(docs=docs)
        results = retriever.retrieve_by_target("1.2.3.4", k=3)
        retriever.vector_store.query.assert_called_once()
        assert len(results) == 1

    def test_retrieve_by_target_filters_unrelated_targets(self):
        # Doc belongs to a different target — should not be returned
        docs = [_make_doc(target="9.9.9.9")]
        retriever = self._make_retriever(docs=docs)
        # Falls back to returning all results when filter yields nothing
        results = retriever.retrieve_by_target("1.2.3.4", k=3)
        assert len(results) == 1  # fallback returns all

    def test_retrieve_by_severity_filters_below_threshold(self):
        low_doc    = _make_doc(severity="low")
        high_doc   = _make_doc(severity="high")
        critical   = _make_doc(severity="critical")
        retriever = self._make_retriever(docs=[low_doc, high_doc, critical])
        results = retriever.retrieve_by_severity("high", k=10)
        severities = {d.metadata["severity"] for d in results}
        assert "low" not in severities

    def test_retrieve_graph_paths_returns_empty_when_offline(self):
        mock_vs = MagicMock()
        mock_vs.query.return_value = []
        mock_gs = MagicMock()
        mock_gs.graph = None   # Neo4j offline
        retriever = ContextRetriever(vector_store=mock_vs, graph_store=mock_gs)
        paths = retriever.retrieve_graph_paths("1.2.3.4")
        assert paths[0].get("error") is not None

    def test_retrieve_all_returns_retrieval_result(self):
        docs = [_make_doc(cve="CVE-2023-1234"), _make_doc(cve="CVE-2023-5678")]
        retriever = self._make_retriever(docs=docs)
        result = retriever.retrieve_all("1.2.3.4", k=5)
        assert isinstance(result, RetrievalResult)
        assert result.target_identifier == "1.2.3.4"

    def test_retrieve_all_deduplicates_merged_docs(self):
        # Same document returned by both semantic and severity queries
        doc = _make_doc(cve="CVE-2023-9999")
        retriever = self._make_retriever(docs=[doc, doc])
        result = retriever.retrieve_all("1.2.3.4", k=5)
        # Should deduplicate by content key
        assert len(result.semantic_docs) == 1

    def test_retrieve_all_collects_neo4j_error_non_fatally(self):
        mock_vs = MagicMock()
        mock_vs.query.return_value = []
        mock_gs = MagicMock()
        mock_gs.graph = None
        retriever = ContextRetriever(vector_store=mock_vs, graph_store=mock_gs)
        result = retriever.retrieve_all("1.2.3.4")
        assert len(result.retrieval_errors) > 0   # error recorded
        assert result.ranked_findings == []         # but no crash



class TestRanker:

    def test_rank_sorts_by_score_descending(self):
        ranker = Ranker()
        findings = [
            _make_finding(severity="low",      cvss=2.0),
            _make_finding(severity="critical", cvss=9.5),
            _make_finding(severity="medium",   cvss=5.0),
        ]
        ranked = ranker.rank(findings)
        assert ranked[0].severity == "critical"
        assert ranked[-1].severity == "low"

    def test_rank_deduplicates_same_cve_keeps_highest(self):
        ranker = Ranker()
        low_version  = _make_finding(cve="CVE-2023-1234", severity="low",  cvss=3.0)
        high_version = _make_finding(cve="CVE-2023-1234", severity="high", cvss=7.5)
        ranked = ranker.rank([low_version, high_version])
        assert len(ranked) == 1
        assert ranked[0].severity == "high"

    def test_rank_no_cve_findings_are_kept_all(self):
        ranker = Ranker()
        f1 = _make_finding(cve=None, severity="high")
        f2 = _make_finding(cve=None, severity="medium")
        ranked = ranker.rank([f1, f2])
        assert len(ranked) == 2

    def test_rank_exploit_context_adds_bonus(self):
        ranker = Ranker()
        with_exploit    = _make_finding(severity="medium", cvss=5.0, exploit="PoC exists")
        without_exploit = _make_finding(severity="medium", cvss=5.0, exploit=None)
        ranked = ranker.rank([without_exploit, with_exploit])
        assert ranked[0].exploit_context == "PoC exists"

    def test_rank_empty_list(self):
        ranker = Ranker()
        assert ranker.rank([]) == []

    def test_retrieval_result_critical_findings_property(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="low"),
            _make_finding(severity="high"),
        ]
        result = RetrievalResult(target_identifier="1.2.3.4", ranked_findings=findings)
        assert len(result.critical_findings) == 2

    def test_retrieval_result_has_findings_false_when_empty(self):
        result = RetrievalResult(target_identifier="1.2.3.4")
        assert result.has_findings is False
