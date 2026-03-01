"""
Ranker: deduplicates and scores a flat list of RankedFinding objects.

Scoring formula per finding:
    score = severity_weight + normalised_cvss_score + exploit_context_bonus

severity_weight mapping:
    critical → 4.0
    high     → 3.0
    medium   → 2.0
    low      → 1.0
    info     → 0.0

normalised_cvss_score = cvss_score / 10.0   (CVSS max is 10.0)

exploit_context_bonus = 1.0 if Tavily exploit context is non-empty, else 0.0

Deduplication: if multiple findings share the same primary_cve, keep the one
with the highest cvss_score (or highest severity as fallback).
"""
from typing import Dict, List
from .search_models import RankedFinding

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 4.0,
    "high":     3.0,
    "medium":   2.0,
    "low":      1.0,
    "info":     0.0,
}


class Ranker:
    def rank(self, findings: List[RankedFinding]) -> List[RankedFinding]:
        """
        Deduplicates findings by CVE, computes scores, and returns a
        sorted list (highest score first).
        """
        deduplicated = self._deduplicate(findings)
        for finding in deduplicated:
            finding.score = self._compute_score(finding)
        return sorted(deduplicated, key=lambda f: f.score, reverse=True)

    # Private helpers

    def _deduplicate(self, findings: List[RankedFinding]) -> List[RankedFinding]:
        """
        For each unique (target, primary_cve) pair keep only the finding with
        the highest CVSS or severity. Findings without a CVE are kept as-is.
        """
        cve_buckets: Dict[str, RankedFinding] = {}    # key: "target::cve_id"
        no_cve: List[RankedFinding] = []

        for f in findings:
            if not f.primary_cve:
                no_cve.append(f)
                continue

            key = f"{f.target}::{f.primary_cve}"
            if key not in cve_buckets:
                cve_buckets[key] = f
            else:
                existing = cve_buckets[key]
                # Prefer higher cvss_score; fall back to severity weight
                if self._numeric_severity(f) > self._numeric_severity(existing):
                    cve_buckets[key] = f

        return list(cve_buckets.values()) + no_cve

    def _compute_score(self, finding: RankedFinding) -> float:
        severity_weight    = _SEVERITY_WEIGHTS.get(finding.severity.lower(), 0.0)
        normalised_cvss    = (finding.cvss_score or 0.0) / 10.0
        exploit_bonus      = 1.0 if finding.exploit_context else 0.0
        return severity_weight + normalised_cvss + exploit_bonus

    def _numeric_severity(self, finding: RankedFinding) -> float:
        """Returns a float so we can compare two findings' severity numerically."""
        score = _SEVERITY_WEIGHTS.get(finding.severity.lower(), 0.0)
        return score + (finding.cvss_score or 0.0) / 10.0
