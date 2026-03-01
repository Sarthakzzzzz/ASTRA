#!/usr/bin/env python3
"""Test AI command generation with new format."""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from orchestrator.core.findings import StandardFinding
from orchestrator.core.ai.planning_agent import analyze_dynamic_scan

findings = [
    StandardFinding(
        id="1",
        source_tool="nmap",
        finding_type='port',
        finding_value='SSH on 22',
        target='scanme.nmap.org',
        capability='ssh_service',
        risk_level='enum',
    ),
    StandardFinding(
        id="2",
        source_tool="nuclei",
        finding_type='vulnerability',
        finding_value='Apache mod_negotiation',
        target='http://scanme.nmap.org',
        capability='web_exposed',
        risk_level='exploit',
    )
]

print(f"Testing AI command generation with {len(findings)} findings...")
print("Calling analyze_dynamic_scan...")
try:
    result = analyze_dynamic_scan(findings, ['nmap', 'whatweb'])
    print("analyze_dynamic_scan call completed.")
except Exception as e:
    print(f"Error during analyze_dynamic_scan: {e}")
    # Depending on desired behavior, you might want to exit or handle further
    # For this test script, we'll just print and let it continue if result is not set
    result = None # Ensure result is defined for subsequent checks

if result is not None:
    print(f"\nResult type: {type(result)}")
    if isinstance(result, list) and len(result) > 0:
        print(f"??? Got {len(result)} recommendations:")
        for r in result:
            print(f"  - Tool: {r.get('tool')}")
            print(f"    Cmd:  {r.get('command')}")
    else:
        print("No recommendations generated or result is not a list.")
else:
    print("analyze_dynamic_scan did not return a result due to an error.")
