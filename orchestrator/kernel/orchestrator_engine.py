"""
The core orchestration engine.
Supports both static (pre-defined) and dynamic (adaptive) scanning modes.
Coordinates the entire scan process, from dependency resolution to execution and parsing.
"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from . import scanner_resolver as dependencies, tool_executor as runner, processing as parsers, helpers as utils


def run_orchestrator(primary_target: str, enable_arg: str, concurrency: int, mode: str, dry_run=False):
    """
    The main orchestration function. Yields log lines for real-time display.
    """
    sanitized_target = utils.sanitize_target(primary_target)
    os.makedirs("orchestrator/results/raw", exist_ok=True)

    # --- Initial Setup ---
    enabled_scanners = dependencies.resolve_enabled_scanners(enable_arg)
    yield f"[+] Mode selected: '{mode.upper()}'\n"
    yield f"[+] Initial scanners: {enabled_scanners}\n"

    # --- Route to the correct mode ---
    if mode == 'dynamic':
        yield from _run_dynamic_mode(
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


from .adaptive_scanner import run_dynamic_mode

def _run_dynamic_mode(target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
    """
    Adapter wrapper to call the newly extracted run_dynamic_mode function
    from adaptive_scanner.py while passing _execute_group.
    """
    yield from run_dynamic_mode(
        target, enabled_scanners, concurrency, dry_run, _execute_group
    )



def _run_command_collect(cmd_args, tool_name, url, dry_run):
    """
    Wraps the run_command generator into a plain function that collects all
    output into a list. This is required because ThreadPoolExecutor cannot
    execute a generator lazily — it must be fully consumed inside the worker
    thread so the subprocess actually runs there.
    """
    return list(runner.run_command(cmd_args, tool_name, url, dry_run))


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

    # 2. Execute commands concurrently.
    # IMPORTANT: runner.run_command is a generator. We must wrap it in
    # _run_command_collect so the subprocess actually executes inside the
    # worker thread rather than being lazily iterated on the main thread.
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {
            executor.submit(_run_command_collect, task['cmd'], task['tool'], task['url'], dry_run): task
            for task in tasks_to_run
        }

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


