from rag.research_agent.phase2_database.graph_store import AttackGraphStore

def test_neo4j_insertion():
    print("Connecting to Neo4j...")
    store = AttackGraphStore()
    
    if not store.graph:
        print("Failed to connect to Neo4j. Check your .env credentials.")
        return

    print("Connection successful. Pushing test finding data...")

    test_findings = [
        {
            "type": "service",
            "target": "10.0.0.5",
            "port": "443",
            "service": "https",
            "product": "nginx",
            "version": "1.18.0"
        },
        {
            "type": "vulnerability",
            "target": "10.0.0.5",
            "name": "Nginx Off-by-one Error",
            "cves": ["CVE-2022-41741"],
            "severity": "high"
        },
        {
            "type": "vulnerability",
            "target": "10.0.0.5",
            "name": "OpenSSL Heartbleed",
            "cves": ["CVE-2014-0160"],
            "severity": "critical"
        }
    ]

    try:
        # Ingest the findings which creates the nodes and relationships
        store.ingest_findings(test_findings)
        
        # We also want to query and prove they are there!
        print("\n--- Verifying Insertion ---")
        result = store.graph.query("MATCH (n) RETURN COUNT(n) as total_nodes")
        print(f"Total Nodes in Database: {result[0]['total_nodes']}")
        
        print("\nSample Data:")
        sample = store.graph.query("MATCH (a:Asset)-[r]->(b) RETURN a.ip as Asset, type(r) as Relationship, labels(b) as TargetNode LIMIT 5")
        for row in sample:
            print(f" - {row['Asset']} --[{row['Relationship']}]--> {row['TargetNode']}")
            
        print("\nSuccess! You can now run `MATCH (n) RETURN n` in the Neo4j Browser to see the visual graph.")
    except Exception as e:
        print(f"Error during ingestion: {e}")

if __name__ == "__main__":
    test_neo4j_insertion()
