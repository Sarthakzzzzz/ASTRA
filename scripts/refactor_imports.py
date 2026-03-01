import os
import glob

replacements = {
    "rag.research_agent.phase1_extraction.rag_extractor": "rag.threat_intel.extractors.cve_enricher",
    "rag.research_agent.phase2_database.document_processor": "rag.threat_intel.database.doc_formatter",
    "rag.research_agent.phase2_database.graph_store": "rag.threat_intel.database.neo4j_store",
    "rag.research_agent.phase2_database.vector_store": "rag.threat_intel.database.chroma_store",
    "rag.research_agent.phase3_retrieval.context_retriever": "rag.threat_intel.search.semantic_search",
    "rag.research_agent.phase3_retrieval.ranker": "rag.threat_intel.search.result_ranker",
    "rag.research_agent.phase3_retrieval.retrieval_result": "rag.threat_intel.search.search_models",
    "rag.attack_path_agent.generator": "rag.attack_chain.path_generator",
    "rag.attack_path_agent.retriever": "rag.attack_chain.path_retriever",
    "rag.attack_path_agent.prompt_builder": "rag.attack_chain.prompt_builder",
    "rag.workflow": "rag.pipeline"
}

def process_file(file_path):
    with open(file_path, "r") as f:
        content = f.read()
        
    original = content
    for old, new in replacements.items():
        content = content.replace(old, new)
        
    if content != original:
        with open(file_path, "w") as f:
            f.write(content)
        print(f"Updated {file_path}")

for root_dir in ["rag", "tests", "orchestrator", "."]:
    if root_dir == ".":
        files = glob.glob("*.py")
    else:
        files = glob.glob(f"{root_dir}/**/*.py", recursive=True)
    
    for py_file in files:
        if "venv" not in py_file:
            process_file(py_file)

print("Refactor complete.")
