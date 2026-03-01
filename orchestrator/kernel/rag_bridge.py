from typing import List, Set

def run_rag_pipeline(target: str, master_findings_list: List, executed_tools: Set[str]):
    """
    Executes the RAG Enrichment and Attack Path generation phases.
    Extracts canonical IPs for Neo4j from the findings.
    Yields log lines tracing the RAG process.
    """
    if not master_findings_list:
        yield "\n[RAG] Skipping RAG pipeline — no findings to enrich.\n"
        return

    yield "\n[RAG] ===== STARTING RAG ENRICHMENT & ATTACK PATH GENERATION =====\n"

    try:
        from rag.pipeline.nodes import rag_enrichment_node, attack_path_node
        from rag.pipeline.state import GraphState

        yield "[RAG] Phase 1: Enriching findings via NVD/Tavily and persisting to Neo4j...\n"
        
        # Resolve canonical IP for Neo4j — nmap always stores findings by IP,
        # so we extract from findings rather than using the hostname-based target string.
        canonical_target = target
        for f in master_findings_list:
            t = getattr(f, 'target', None) or ''
            # Pick the first finding target that looks like a plain IP
            import re
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', t):
                canonical_target = t
                break

        rag_state = GraphState(
            target_identifier=canonical_target,
            scan_findings=master_findings_list,
            executed_tools=list(executed_tools),
            recommended_tools=[],
            enriched_rag_data=[],
            attack_path_graph=None,
            error=None
        )

        rag_state = rag_enrichment_node(rag_state)

        if rag_state.get("error"):
            yield f"[!] RAG Enrichment error: {rag_state['error']}\n"
        else:
            enriched_count = len(rag_state.get("enriched_rag_data", []))
            yield f"[RAG] Enriched {enriched_count} findings → stored in ChromaDB & Neo4j.\n"

        yield "[RAG] Phase 2: Generating attack path graph...\n"
        rag_state = attack_path_node(rag_state)

        if rag_state.get("error"):
            yield f"[!] Attack path error: {rag_state['error']}\n"
        else:
            attack_graph = rag_state.get("attack_path_graph")
            if attack_graph:
                # Save DOT graph to file
                graph_path = f"orchestrator/results/{target}_attack_path.dot"
                with open(graph_path, "w") as gf:
                    gf.write(attack_graph)
                yield f"[RAG] Attack path generated → {graph_path}\n"
                yield f"\n[RAG] === ATTACK PATH (DOT) ===\n{attack_graph}\n"
            else:
                yield "[RAG] No attack path generated (insufficient findings for a chain).\n"

    except Exception as e:
        import traceback
        yield f"[!] RAG/Attack Path pipeline failed: {e}\n"
        traceback.print_exc()
