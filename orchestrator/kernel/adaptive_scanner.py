from typing import List, Set
from . import scanner_resolver as dependencies, tool_executor as runner
from .rag_bridge import run_rag_pipeline

def run_dynamic_mode(target: str, enabled_scanners: list, concurrency: int, dry_run: bool, execute_group_fn):
    """
    Runs an adaptive scan with AI-driven tool recommendations.
    Iteratively executes scanners and uses AI to decide what to scan next.
    Takes execute_group_fn as a dependency injected callback to avoid circular imports.
    """
    from .brain.decision_agent import analyze_dynamic_scan

    master_findings_list = []
    executed_tools = set()
    iteration = 0
    max_iterations = 3  # Prevent infinite loops

    yield "[+] Starting dynamic AI-driven scan...\n"

    # First iteration: Run initial scanners
    initial_groups = dependencies.build_execution_groups(enabled_scanners)
    yield "[+] Initial scanners to execute:\n"
    for i, group in enumerate(initial_groups):
        yield f"    - Group {i+1}: {group}\n"

    for group in initial_groups:
        yield f"\n[~] Running initial group: {group}\n"
        for result in execute_group_fn(group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
            else:
                master_findings_list.append(result)
        executed_tools.update(group)

    # Iterative AI-driven scanning
    while iteration < max_iterations:
        yield f"\n[*] Iteration {iteration}: Collected {len(master_findings_list)} findings\n"
        
        # Summarize findings by risk level
        yield "[+] Findings by risk level:\n"
        risk_counts = {}
        for f in master_findings_list:
            risk = getattr(f, 'risk_level', 'unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        for risk, count in risk_counts.items():
            yield f"    - {risk}: {count}\n"

        # Get AI recommendations for next tools using the new RAG architecture
        try:
            yield "\n[AI] Calling RAG Recommendation Node to analyze findings...\n"
            from rag.pipeline.nodes import recommendation_node
            from rag.pipeline.state import GraphState
            
            temp_state = GraphState(
                target_identifier=target,
                scan_findings=master_findings_list,
                executed_tools=list(executed_tools),
                recommended_tools=[],
                enriched_rag_data=[],
                attack_path_graph=None,
                error=None
            )
            
            new_state = recommendation_node(temp_state)
            
            if new_state.get("error"):
                yield f"[!] RAG Recommendation Error: {new_state['error']}\n"
                
            recommendations = new_state.get("recommended_tools", [])
            
            # Filter recommendations for tools that haven't been executed yet
            new_recommendations = [r for r in recommendations if r.get("tool") not in executed_tools]
            if not new_recommendations:
                yield "[AI] All recommended tools already executed. Scan complete.\n"
                break

            yield f"[AI] Executing {len(new_recommendations)} AI-recommended actions...\n"

            for i, rec in enumerate(new_recommendations, 1):
                tool_name = rec.get("tool", "")
                command   = rec.get("command", "")
                rationale = rec.get("rationale", "No rationale provided.")

                if not tool_name or not command:
                    continue

                yield f"\n{'─' * 60}\n"
                yield f"[AI] Recommendation {i}/{len(new_recommendations)}\n"
                yield f"     Tool     : {tool_name}\n"
                yield f"     Rationale: {rationale}\n"
                yield f"     Command  : {command}\n"
                yield f"{'─' * 60}\n\n"

                for result in runner.run_command_direct(command, tool_name, target, dry_run):
                    if isinstance(result, str):
                        yield result
                    else:
                        master_findings_list.append(result)

                executed_tools.add(tool_name)

        except Exception as e:
            import traceback
            yield f"[!] AI recommendation failed: {e}\n"
            traceback.print_exc()
            yield "[!] Continuing with manual analysis.\n"
            break

        iteration += 1

    # Final summary
    yield f"\n[*] ===== FINAL SCAN SUMMARY =====\n"
    yield f"[*] Total findings collected: {len(master_findings_list)}\n"
    yield f"[*] Tools executed: {list(executed_tools)}\n"
    yield f"[*] Iterations completed: {iteration}\n"

    # AI-generated summary
    if master_findings_list:
        try:
            yield "\n[AI] Generating comprehensive security analysis...\n"
            ai_summary = analyze_dynamic_scan(master_findings_list, list(executed_tools), summary_mode=True)
            if ai_summary and isinstance(ai_summary, dict):
                summary_text = ai_summary.get('summary', 'No summary available')
                yield f"\n[AI] === SECURITY ANALYSIS SUMMARY ===\n{summary_text}\n"
        except Exception as e:
            yield f"[!] AI summary generation failed: {e}\n"

    if master_findings_list:
        # Log findings summary
        yield "[+] Findings by risk level:\n"
        risk_counts = {}
        high_risk_findings = []
        
        for f in master_findings_list:
            risk = getattr(f, 'risk_level', 'unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            if risk == 'exploit':
                high_risk_findings.append(f)
        
        for risk, count in sorted(risk_counts.items()):
            yield f"    - {risk}: {count}\n"

        if high_risk_findings:
            yield f"\n[!] {len(high_risk_findings)} CRITICAL FINDINGS DETECTED:\n"
            for f in high_risk_findings[:10]:
                cap = getattr(f, 'capability', 'unknown')
                severity = getattr(f, 'severity', 'unknown')
                yield f"    [CRITICAL] {cap}: {f.finding_value}\n"
                yield f"              Target: {f.target} | Severity: {severity}\n"

    # Execute RAG phase
    yield from run_rag_pipeline(target, master_findings_list, executed_tools)
