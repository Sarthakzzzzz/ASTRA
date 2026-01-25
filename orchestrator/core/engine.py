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
    os.makedirs("output/raw", exist_ok=True)

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
        yield from _run_static_mode(sanitized_target, enabled_scanners, concurrency, dry_run)


def _run_static_mode(target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
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
        for result in _execute_group(group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
            else:
                master_findings_list.append(result)


def _run_dynamic_mode(graph, target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
    """
    Runs an adaptive scan with AI-driven tool recommendations.
    Iteratively executes scanners and uses AI to decide what to scan next.
    """
    from .ai.planning_agent import analyze_dynamic_scan

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
        for result in _execute_group(group, target, master_findings_list, concurrency, dry_run):
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

        # Get AI recommendations for next tools
        try:
            yield "\n[AI] Calling AI agent to recommend next tools...\n"
            recommendations = analyze_dynamic_scan(master_findings_list, list(executed_tools))
            
            if not recommendations:
                yield "[AI] No additional tools recommended. Scan complete.\n"
                break
            
            # Filter recommendations for tools that haven't been executed yet
            new_recommendations = [r for r in recommendations if r.get("tool") not in executed_tools]
            if not new_recommendations:
                yield "[AI] All recommended tools already executed. Scan complete.\n"
                break

            yield f"[AI] Executing {len(new_recommendations)} AI-recommended actions...\n"

            # Execute the recommended tools with AI-specified commands
            for rec in new_recommendations:
                tool_name = rec.get("tool", "")
                command = rec.get("command", "")
                
                if not tool_name or not command:
                    continue
                
                yield f"[AI] Executing: {command}\n"
                
                # Run the custom command directly
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

        # Log high-value findings with details
        if high_risk_findings:
            yield f"\n[!] {len(high_risk_findings)} CRITICAL FINDINGS DETECTED:\n"
            for f in high_risk_findings[:10]:
                cap = getattr(f, 'capability', 'unknown')
                severity = getattr(f, 'severity', 'unknown')
                yield f"    [CRITICAL] {cap}: {f.finding_value}\n"
                yield f"              Target: {f.target} | Severity: {severity}\n"


def _execute_group(group: list, target: str, master_findings: list, concurrency: int, dry_run: bool):
    """
    Helper function to execute a single group of tools and parse their results.
    Yields log lines (str) and StandardFinding objects.
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

    # 2. Execute commands concurrently
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(runner.run_command, task['cmd'], task['tool'], task['url'], dry_run): task for task in tasks_to_run}

        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                for line in future.result():
                    yield line
            except Exception as e:
                yield f"[!!!] ERROR in task '{task['tool']} on {task['url']}': {e}\n"

    # 3. After all tools in the group finish, parse their results
    yield f"[*] Parsing results for group: {group}\n"
    for task in tasks_to_run:
        parser_func = parsers.get_parser_for_tool(task['tool'])
        if parser_func:
            try:
                # Pass the URL for context, needed by some parsers
                findings = parser_func(task['file'], task.get('url'))
                yield f"[+] [{task['tool']}] Parsed {len(findings)} findings\n"
                for finding in findings:
                    yield finding  # Yield the structured finding object
            except Exception as e:
                yield f"[!] Error parsing output for {task['tool']} from {task['file']}: {e}\n"


