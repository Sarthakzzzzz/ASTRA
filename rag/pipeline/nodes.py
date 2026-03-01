
# Core Orchestrator components
from orchestrator.kernel.brain.decision_agent import analyze_dynamic_scan

# Research Agent (RAG Enrichment) Phase 1 & 2 components
from rag.threat_intel.extractors.cve_enricher import ResearchAgentExtractor
from rag.threat_intel.database.doc_formatter import DocumentProcessor
from rag.threat_intel.database.chroma_store import VulnerabilityVectorStore
from rag.threat_intel.database.neo4j_store import AttackGraphStore

# Attack Path Agent Phase 4 components
from rag.attack_chain.path_retriever import AttackPathRetriever
from rag.attack_chain.prompt_builder import AttackPathPromptBuilder
from rag.attack_chain.path_generator import AttackPathGenerator

from rag.pipeline.state import GraphState

def recommendation_node(state: GraphState) -> GraphState:
    findings = state.get("scan_findings", [])
    if not findings:
        return state
        
    print(f"--- [Recommendation Node] Analyzing {len(findings)} findings ---")
    
    try:
        # Assuming we have generic tools for context. Modify as needed for production.
        executed = state.get("executed_tools", [])
        recommendations = analyze_dynamic_scan(findings, executed)
        state["recommended_tools"] = recommendations
    except Exception as e:
        state["error"] = f"Recommendation Agent Error: {e}"
        state["recommended_tools"] = []
        
    return state


def rag_enrichment_node(state: GraphState) -> GraphState:
    findings = state.get("scan_findings", [])
    if not findings:
        return state
        
    print(f"--- [RAG Enrichment Node] Enriching findings ---")
    
    try:
        # Phase 1: Extractions and Enrichment
        extractor = ResearchAgentExtractor()
        enriched_findings = []
        
        # For this node, we assume the 'scan_findings' are already parsed from nuclei/nmap
        # In a real run, the orchestrator might pass raw JSON dicts here. We will enrich them.
        from copy import deepcopy
        import dataclasses
        from orchestrator.kernel.finding_models import StandardFinding

        for finding in findings:
            # Handle both raw dicts (from mock data in UI) and StandardFinding dataclasses (from active engine)
            if dataclasses.is_dataclass(finding) or isinstance(finding, StandardFinding):
                f_data = dataclasses.asdict(finding)
                f_type = f_data.get("finding_type", "unknown")
                cves = f_data.get("details", {}).get("cves", [])
                f_data["type"] = "vulnerability" if f_type in ["vulnerability", "exploit"] else "service"
                f_data["cves"] = cves
                
                # Make sure fields expected by DB mappers exist
                f_data["port"] = str(f_data.get("port") or "unknown")
                f_data["service"] = str(f_data.get("service") or "unknown")
                f_data["product"] = str(f_data.get("os") or "unknown")
                
                enriched_finding = f_data
            else:
                enriched_finding = deepcopy(finding)
                
            if enriched_finding.get("type") == "vulnerability" and enriched_finding.get("cves"):
                primary_cve = enriched_finding["cves"][0]
                enriched_finding["nvd_details"] = extractor.get_nvd_details.run(primary_cve)
                enriched_finding["exploit_context"] = extractor.get_exploit_context.run(primary_cve)
            enriched_findings.append(enriched_finding)
            
        state["enriched_rag_data"] = enriched_findings
        
        # Phase 2 & 3: Database Mapping
        doc_processor = DocumentProcessor()
        docs = doc_processor.process_findings(enriched_findings)
        
        vector_store = VulnerabilityVectorStore()
        vector_store.ingest_documents(docs)
        
        graph_store = AttackGraphStore()
        graph_store.ingest_findings(enriched_findings)
        
    except Exception as e:
        state["error"] = f"RAG Enrichment Error: {e}"
        state["enriched_rag_data"] = []
        
    return state

def attack_path_node(state: GraphState) -> GraphState:
    target = state.get("target_identifier")
    if not target:
        return state
        
    print(f"--- [Attack Path Node] Generating map for {target} ---")
    
    try:
        retriever = AttackPathRetriever()
        prompt_builder = AttackPathPromptBuilder()
        generator = AttackPathGenerator()
        
        # Phase 3 retrieval: ranked, deduplicated context from ChromaDB + Neo4j
        context = retriever.retrieve_context(target)

        # Log any non-fatal retrieval errors (e.g. Neo4j offline)
        for err in context.get("retrieval_errors", []):
            print(f"  [Phase3] Retrieval note: {err}")

        # Log ranked findings count for visibility
        ranked = context.get("ranked_findings", [])
        if ranked:
            print(f"  [Phase3] {len(ranked)} ranked findings available for prompt.")
            for f in ranked[:5]:
                print(f"    [{f.severity.upper()}] {f.name} | score={f.score:.2f} | CVE={f.primary_cve}")

        prompt = prompt_builder.build_prompt(target, context)
        
        attack_path_dot = generator.generate(prompt, target_identifier=target)
        state["attack_path_graph"] = attack_path_dot
        
    except Exception as e:
        state["error"] = f"Attack Path Generation Error: {e}"
        
    return state
