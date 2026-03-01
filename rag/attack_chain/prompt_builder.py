from typing import Dict, Any, List
from langchain_core.documents import Document

class AttackPathPromptBuilder:
    def __init__(self):
        """Initializes the Prompt Builder for the Attack Path Agent."""
        self.system_prompt = """
You are an Expert Red Teamer and Attack Path Modeler.
Your task is to analyze the structural network layout and the semantic threat intelligence provided to you.
Determine the most viable attack paths a hacker would take to compromise the system.
Output your findings as a strict Graphviz DOT format to visualize the intrusion chain.

CRITICAL INSTRUCTIONS:
- ONLY output valid Graphviz DOT format.
- Do NOT wrap your output in markdown code blocks (e.g., no ```dot or ```).
- Start immediately with 'digraph AttackPath {' and end with '}'.
- Use appropriate styling, colors, and labels for nodes (e.g., shape=box for Assets, color=red for Vulnerabilities).
"""

    def build_prompt(self, target_identifier: str, context: Dict[str, Any]) -> str:
        """
        Synthesizes the master prompt combining user target, structural paths, 
        and semantic vulnerability context.
        """
        prompt = f"{self.system_prompt}\n\n"
        prompt += f"Target Identifier: {target_identifier}\n\n"
        
        prompt += "--- STRUCTURAL DATA (Neo4j) ---\n"
        prompt += "Here is the exact layout of the exposed assets, services, and vulnerabilities:\n"
        structural_data = context.get("structural_paths", [])
        if structural_data and "error" not in structural_data[0]:
            for path_record in structural_data:
                # Simplified stringification of the path for the LLM
                prompt += f"{str(path_record)}\n"
        else:
            prompt += "No structural paths found or graph DB is unavailable.\n"
            
        prompt += "\n--- SEMANTIC DATA (ChromaDB) ---\n"
        prompt += "Here is the threat intelligence regarding the vulnerabilities found on those services:\n"
        semantic_data: List[Document] = context.get("semantic_context", [])
        if semantic_data:
            for idx, doc in enumerate(semantic_data, 1):
                prompt += f"Vulnerability {idx} [{doc.metadata.get('primary_cve', 'N/A')}]:\n"
                prompt += f"{doc.page_content}\n---\n"
        else:
            prompt += "No semantic context found in the vector DB.\n"
            
        return prompt
