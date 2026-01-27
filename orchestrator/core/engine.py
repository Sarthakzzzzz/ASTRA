"""
The core orchestration engine.
Supports both static (pre-defined) and dynamic (adaptive) scanning modes.
Coordinates the entire scan process, from dependency resolution to execution and parsing.
"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from . import dependencies, runner, parsers, rules_engine, utils
from .graph import AstraGraph


def run_orchestrator(primary_target: str, enable_arg: str, concurrency: int, mode: str, dry_run=False):
    """
    The main orchestration function. Yields log lines for real-time display.
    """
    sanitized_target = utils.sanitize_target(primary_target)
    os.makedirs("orchestrator/output/raw", exist_ok=True)

    # --- Initial Setup ---
    enabled_scanners = dependencies.resolve_enabled_scanners(enable_arg)
    yield f"[+] Mode selected: '{mode.upper()}'\n"
    yield f"[+] Initial scanners: {enabled_scanners}\n"

    # --- Route to the correct mode ---
    if mode == 'dynamic':
        graph = AstraGraph()
        graph.add_asset(sanitized_target)
        yield from _run_dynamic_mode(
            graph,
            sanitized_target,
            enabled_scanners,
            concurrency,
            dry_run
        )
    else:
        graph = AstraGraph()
        graph.add_asset(sanitized_target)
        yield from _run_static_mode(graph, sanitized_target, enabled_scanners, concurrency, dry_run)


def _run_static_mode(graph, target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
    """
    Runs a fixed, pre-calculated execution plan from start to finish.
    """
    execution_groups = dependencies.build_execution_groups(enabled_scanners)
    yield "[+] Static execution plan calculated:\n"
    for i, group in enumerate(execution_groups):
        yield f"    - Group {i+1}: {group}\n"

    master_findings_list = []

    for group in execution_groups:
        yield f"\n[~] Running group: {group}\n"
        for result in _execute_group(graph, group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
            else:
                master_findings_list.append(result)
    
    yield "\n" + "="*50 + "\n"
    yield "[+] SCAN COMPLETE. All static groups finished.\n"
    yield f"[+] Total findings collected: {len(master_findings_list)}\n"
    yield "="*50 + "\n"


def _run_dynamic_mode(graph, target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
    """
    Runs an adaptive scan with AI-driven tool recommendations.
    Iteratively executes scanners and uses AI to decide what to scan next.
    """
    # DIRECT GOOGLE ADK INTEGRATION - planning_agent removed
    from google_adk.agent import ScanAgent
    
    # Initialize Google ADK Agent EARLY
    scan_agent = ScanAgent()

    master_findings_list = []
    executed_tools = set()
    iteration = 0
    max_iterations = 3  # Prevent infinite loops

    yield "[+] Starting dynamic AI-driven scan (Incremental AI Analysis Enabled)...\n"

    # First iteration: Run initial scanners
    initial_groups = dependencies.build_execution_groups(enabled_scanners)
    yield "[+] Initial scanners to execute:\n"
    for i, group in enumerate(initial_groups):
        yield f"    - Group {i+1}: {group}\n"

    for group in initial_groups:
        yield f"\n[~] Running initial group: {group}\n"
        
        # Track tools completing in this group
        tools_completed_in_group = set()
        
        for result in _execute_group(graph, group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
                # Detect tool completion message
                if "Parsed" in result and "findings" in result:
                    # Update AI Reasoning after a tool finishes
                    # Extract tool name from log if possible, or just trigger update
                    # To avoid spamming, we trigger update here
                    try:
                         # Lightweight update - get AI thoughts on current state
                         # We do this non-blocking or just fire-and-wait-briefly
                         # Since recommend_next_scans updates state, calling it is enough
                         # But we only want to do it if we have meaningful findings
                         if master_findings_list:
                             yield f"[AI] Analyzing new findings from completed tool...\n"
                             scan_agent.recommend_next_scans(master_findings_list, list(executed_tools))
                    except Exception as e:
                        yield f"[!] Minimal AI update failed: {e}\n"

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

        # Get AI recommendations DIRECTLY from Google ADK
        try:
            yield "\n[AI] Calling Google ADK Agent for scan recommendations...\n"
            
            # Get structured recommendations from Google ADK
            recommendations = scan_agent.recommend_next_scans(
                master_findings_list, 
                list(executed_tools)
            )
            
            yield f"[AI] Google ADK recommended {len(recommendations)} tools\n"
            
            if not recommendations:
                yield "[AI] No additional tools recommended. Scan complete.\n"
                break
            
            # Filter recommendations for tools that haven't been executed yet
            new_recommendations = [r for r in recommendations if r.get("tool") not in executed_tools]
            if not new_recommendations:
                yield "[AI] All recommended tools already executed. Scan complete.\n"
                break

            yield f"[AI] Executing {len(new_recommendations)} AI-recommended actions...\n"

            # Execute the recommended tools (Google ADK format: tool, target, reason)
            for rec in new_recommendations:
                tool_name = rec.get("tool", "")
                rec_target = rec.get("target", target)
                reason = rec.get("reason", "AI recommendation")
                
                if not tool_name:
                    continue
                
                yield f"[AI] {reason}\n"
                yield f"[AI] Running: {tool_name} on {rec_target}\n"
                
                # Execute tool using standard flow
                # For recommendations, we also want incremental updates
                for result in _execute_group(graph, [tool_name], rec_target, master_findings_list, concurrency, dry_run):
                    if hasattr(result, 'finding_type'):
                        yield f"[+] [{result.source_tool}] Found: {result.finding_type} -> {result.finding_value}\n"
                        master_findings_list.append(result)
                    elif isinstance(result, str):
                        yield result
                        if "Parsed" in result:
                             scan_agent.recommend_next_scans(master_findings_list, list(executed_tools))

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
            final_analysis = scan_agent.analyze_findings(master_findings_list)
            yield f"\n[AI] === SECURITY ANALYSIS SUMMARY ===\n{final_analysis}\n"
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

        # Log high-value findings with details
        if high_risk_findings:
            yield f"\n[!] {len(high_risk_findings)} CRITICAL FINDINGS DETECTED:\n"
            for f in high_risk_findings[:10]:
                cap = getattr(f, 'capability', 'unknown')
                severity = getattr(f, 'severity', 'unknown')
                yield f"    [CRITICAL] {cap}: {f.finding_value}\n"
                yield f"              Target: {f.target} | Severity: {severity}\n"


def _execute_group(graph, group: list, target: str, master_findings: list, concurrency: int, dry_run: bool):
    """
    Helper function to execute a single group of tools and parse their results.
    Yields log lines (str) and StandardFinding objects AS THEY COMPLETE.
    """
    tasks_to_run = []

    # 1. Build the list of all commands for this group
    for tool_name in group:
        scanner_config = dependencies.get_scanner_by_name(tool_name)
        if not scanner_config:
            continue

        if scanner_config.get("requires_url"):
            # Find web service URLs from all findings so far
            web_targets = {f.target for f in master_findings if f.finding_type == "web_service"}
            # Fallback if no web services have been found yet
            if not web_targets:
                web_targets = {utils.ensure_http_scheme(target)}

            for url in web_targets:
                output_file = utils.get_output_filepath(scanner_config, url, target)
                cmd_args = utils.command_builder(scanner_config, url, target, output_file)
                tasks_to_run.append({'tool': tool_name, 'cmd': cmd_args, 'url': url, 'file': output_file})
        else:
            output_file = utils.get_output_filepath(scanner_config, target, target)
            cmd_args = utils.command_builder(scanner_config, target, target, output_file)
            tasks_to_run.append({'tool': tool_name, 'cmd': cmd_args, 'url': target, 'file': output_file})

    # 2. Execute commands concurrently AND PARSE IMMEDIATELY upon completion
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(runner.run_command, task['cmd'], task['tool'], task['url'], dry_run): task for task in tasks_to_run}

        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                # Yield logs from the tool execution FIRST
                for line in future.result():
                    yield line
                
                # IMMEDIATELY Parse results for this completed task
                yield f"[*] Parsing results for {task['tool']}\n"
                parser_func = parsers.get_parser_for_tool(task['tool'])
                if parser_func:
                    try:
                        # Pass the URL for context, needed by some parsers
                        findings = parser_func(task['file'], task.get('url'))
                        yield f"[+] [{task['tool']}] Parsed {len(findings)} findings\n"
                        for finding in findings:
                            # Add finding to graph database
                            graph.add_finding(finding)
                            yield finding  # Yield the structured finding object
                    except Exception as e:
                        yield f"[!] Error parsing output for {task['tool']} from {task['file']}: {e}\n"

            except Exception as e:
                yield f"[!!!] ERROR in task '{task['tool']} on {task['url']}': {e}\n"


