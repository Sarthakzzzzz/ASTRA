"""
Typed dataclasses that represent the outputs of the Phase 3 retrieval layer.
Using dataclasses gives the rest of the pipeline a stable, typed interface
instead of raw dicts that can silently drop fields.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RankedFinding:
    """
    A single enriched finding after deduplication and scoring.

    score is a float computed by the Ranker:
        score = severity_weight + normalised_cvss_score + exploit_context_bonus
    Higher is more critical / more actionable.
    """
    target: str
    name: str
    finding_type: str               # "vulnerability" | "service"
    severity: str                   # nuclei severity string: critical/high/medium/low/info
    primary_cve: Optional[str]
    description: str
    cvss_score: Optional[float]     # from NVD if available
    exploit_context: Optional[str]  # Tavily search snippet if available
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0              # computed by Ranker


@dataclass
class RetrievalResult:
    """
    Fused output from all Phase 3 retrieval sources for a single target.
    Passed directly to the Attack Path Agent's PromptBuilder.
    """
    target_identifier: str
    ranked_findings: List[RankedFinding] = field(default_factory=list)
    structural_paths: List[Dict[str, Any]] = field(default_factory=list)   # raw Neo4j records
    semantic_docs: List[Any] = field(default_factory=list)                  # LangChain Documents
    retrieval_errors: List[str] = field(default_factory=list)               # non-fatal errors

    @property
    def has_findings(self) -> bool:
        return bool(self.ranked_findings)

    @property
    def critical_findings(self) -> List[RankedFinding]:
        return [f for f in self.ranked_findings if f.severity in ("critical", "high")]
