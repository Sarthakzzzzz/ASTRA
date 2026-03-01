import os
import glob

replacements = {
    # Absolute module paths
    "orchestrator.core.ai.client": "orchestrator.kernel.brain.llm_client",
    "orchestrator.core.ai.planning_agent": "orchestrator.kernel.brain.decision_agent",
    "orchestrator.core.ai.exploitdb": "orchestrator.kernel.brain.exploit_search",
    "orchestrator.core.parsers": "orchestrator.kernel.processing",
    "orchestrator.core.engine": "orchestrator.kernel.orchestrator_engine",
    "orchestrator.core.runner": "orchestrator.kernel.tool_executor",
    "orchestrator.core.dynamic_scan": "orchestrator.kernel.adaptive_scanner",
    "orchestrator.core.rag_integration": "orchestrator.kernel.rag_bridge",
    "orchestrator.core.registry": "orchestrator.kernel.scanner_registry",
    "orchestrator.core.dependencies": "orchestrator.kernel.scanner_resolver",
    "orchestrator.core.findings": "orchestrator.kernel.finding_models",
    "orchestrator.core.rules_loader": "orchestrator.kernel.rule_interpreter",
    "orchestrator.core.utils": "orchestrator.kernel.helpers",
    "orchestrator.core": "orchestrator.kernel",
    "orchestrator.rules": "orchestrator.signatures",
    "orchestrator.main": "orchestrator.cli",
    
    # Folder strings
    "orchestrator/results/raw": "orchestrator/results/raw",
    "output/raw": "orchestrator/results/raw",
    
    # Relative imports in orchestrator/kernel
    "from . import dependencies, runner, parsers, utils": "from . import scanner_resolver as dependencies, tool_executor as runner, processing as parsers, helpers as utils",
    "from . import dependencies, runner": "from . import scanner_resolver as dependencies, tool_executor as runner",
    "from .rag_integration import run_rag_pipeline": "from .rag_bridge import run_rag_pipeline",
    "from .ai.planning_agent import analyze_dynamic_scan": "from .brain.decision_agent import analyze_dynamic_scan",
    "from .ai import": "from .brain import",
    "from ..registry import": "from ..scanner_registry import",
    "from ..rules_loader import": "from ..rule_interpreter import",
    "from .exploitdb import": "from .exploit_search import",
}

def process_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            content = f.read()
        except UnicodeDecodeError:
            return

    original = content
    for old, new in replacements.items():
        content = content.replace(old, new)
        
    if content != original:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {file_path}")

# Scan all relevant directories
target_dirs = ["orchestrator", "rag", "tests", "scripts", "."]
for d in target_dirs:
    if d == ".":
        files = glob.glob("*.py")
    else:
        files = glob.glob(f"{d}/**/*.py", recursive=True)
        
    for f in files:
        if ".venv" not in f and "refactor_orchestrator.py" not in f:
            process_file(f)

print("Orchestrator refactor complete.")
