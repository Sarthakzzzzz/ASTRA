import os
from dotenv import load_dotenv
from langchain_neo4j import Neo4jGraph

load_dotenv()

try:
    graph = Neo4jGraph(
        url=os.getenv("NEO4J_URI"),
        username=os.getenv("NEO4J_USERNAME"),
        password=os.getenv("NEO4J_PASSWORD")
    )
    
    print("Checking for Assets...")
    assets = graph.query("MATCH (a:Asset) RETURN a")
    print(f"Total Assets found: {len(assets)}")
    
    print("Checking for Ports...")
    ports = graph.query("MATCH (p:Port) RETURN p")
    print(f"Total Ports found: {len(ports)}")
    
    print("Checking for Services...")
    services = graph.query("MATCH (s:Service) RETURN s")
    print(f"Total Services found: {len(services)}")
    
    print("Checking for Vulnerabilities...")
    vulns = graph.query("MATCH (v:Vulnerability) RETURN v")
    print(f"Total Vulnerabilities found: {len(vulns)}")
    
    print("\nSample Path (Asset -> Port -> Service):")
    sample_path = graph.query("MATCH path=(a:Asset)-[:EXPOSES]->(p:Port)-[:RUNS]->(s:Service) RETURN a.ip, p.port_id, s.name LIMIT 5")
    for row in sample_path:
        print(f"{row['a.ip']} -> {row['p.port_id']} -> {row['s.name']}")

except Exception as e:
    print(f"ERROR: {e}")
