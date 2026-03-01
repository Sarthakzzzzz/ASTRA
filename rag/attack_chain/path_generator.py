import os
from typing import Iterator
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv

from rag.threat_intel.database.neo4j_store import AttackGraphStore

load_dotenv()

class AttackPathGenerator:
    def __init__(self, model_name: str = "gemini-2.5-flash-lite", graph_store: AttackGraphStore = None):
        """Initializes the LLM specifically for streaming Graphviz output."""
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY or GEMINI_API_KEY must be set in the environment.")
            
        # We explicitly configure transport="rest" as noted in our maintenance logs
        self.llm = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
        )
        self.graph_store = graph_store or AttackGraphStore()

    def generate_stream(self, prompt: str, target_identifier: str = None) -> Iterator[str]:
        """
        Sends the master prompt to the LLM, yields the response as a stream,
        and saves the complete generated DOT syntax to Neo4j if a target is provided.
        """
        message = HumanMessage(content=prompt)
        full_response = ""
        
        try:
            for chunk in self.llm.stream([message]):
                content = chunk.content
                full_response += content
                yield content
                
            if target_identifier:
                self._save_to_neo4j(target_identifier, full_response)
                
        except Exception as e:
            yield f"digraph Error {{\n  err [label=\"Error generating graph: {str(e)}\" shape=box color=red];\n}}"

    def generate(self, prompt: str, target_identifier: str = None) -> str:
        """
        Synchronous fallback for generating the entire response at once.
        """
        message = HumanMessage(content=prompt)
        try:
            response = self.llm.invoke([message])
            content = response.content
            if target_identifier:
                self._save_to_neo4j(target_identifier, content)
            return content
        except Exception as e:
            return f"digraph Error {{\n  err [label=\"Error generating graph: {str(e)}\" shape=box color=red];\n}}"
            
    def _save_to_neo4j(self, target_identifier: str, dot_content: str):
        """Saves the generated DOT graph to Neo4j, linked to the target Asset."""
        if not self.graph_store.graph:
            return
            
        query = """
        MATCH (a:Asset {ip: $target})
        MERGE (ap:AttackPath {target_ip: $target})
        SET ap.dot_content = $dot_content, ap.created_at = timestamp()
        MERGE (a)-[:HAS_ATTACK_PATH]->(ap)
        """
        try:
            self.graph_store.graph.query(
                query, 
                params={"target": target_identifier, "dot_content": dot_content}
            )
        except Exception as e:
            print(f"Error saving Attack Path to Neo4j: {e}")
