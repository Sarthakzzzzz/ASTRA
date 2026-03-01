import os
import glob

replacements = {
    "orchestrator/output": "orchestrator/results",
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

target_dirs = ["orchestrator", "rag", "tests", "scripts", "signatures", "."]
for d in target_dirs:
    if d == ".":
        files = glob.glob("*.py")
    else:
        files = glob.glob(f"{d}/**/*", recursive=True)
        
    for f in files:
        if os.path.isfile(f) and ".venv" not in f and "refactor_output_to_results.py" not in f:
            process_file(f)

print("Output to Results refactor complete.")
