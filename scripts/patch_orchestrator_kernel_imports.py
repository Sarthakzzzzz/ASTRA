import os

files_to_patch = [
    "tests/test_e2e_pipeline.py",
    "tests/test_engine_rag.py",
    "streamlit_app.py",
    "orchestrator/cli.py"
]

replacements = [
    ("from orchestrator.kernel import engine, utils, dependencies", "from orchestrator.kernel import orchestrator_engine as engine, helpers as utils, scanner_resolver as dependencies"),
    ("from orchestrator.kernel import engine, utils", "from orchestrator.kernel import orchestrator_engine as engine, helpers as utils"),
    ("from orchestrator.kernel import engine", "from orchestrator.kernel import orchestrator_engine as engine"),
    ("from orchestrator.kernel import utils", "from orchestrator.kernel import helpers as utils"),
    ("from orchestrator.kernel import dependencies", "from orchestrator.kernel import scanner_resolver as dependencies"),
    ("import orchestrator.kernel.engine", "import orchestrator.kernel.orchestrator_engine as engine")
]

for file_path in files_to_patch:
    if not os.path.exists(file_path):
        continue
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    original = content
    for old, new in replacements:
        content = content.replace(old, new)
        
    if content != original:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Patched {file_path}")

print("Patch complete.")
