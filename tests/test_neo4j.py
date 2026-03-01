from langchain_neo4j import Neo4jGraph
from dotenv import load_dotenv
import os

load_dotenv()

try:
    print(f"Attempting to connect to Neo4j at: {os.getenv('NEO4J_URI')}")
    graph = Neo4jGraph(
        url=os.getenv("NEO4J_URI"),
        username=os.getenv("NEO4J_USERNAME"),
        password=os.getenv("NEO4J_PASSWORD")
    )
    result = graph.query("RETURN 'Connection Successful!' AS message")
    print(f"✅ SUCCESS: {result[0]['message']}")
except Exception as e:
    print(f"❌ ERROR: Connection failed.\nDetails: {e}")
