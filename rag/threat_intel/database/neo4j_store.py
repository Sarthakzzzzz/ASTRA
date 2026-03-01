import os
from typing import List, Dict, Any
from langchain_neo4j import Neo4jGraph
from dotenv import load_dotenv

load_dotenv()

class AttackGraphStore:
    def __init__(self, url: str = None, username: str = None, password: str = None):
        """Initializes connection to the Neo4j Graph Database."""
        self.url = url or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.username = username or os.getenv("NEO4J_USERNAME", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "password")
        
        # This will fail fast if Neo4j is not running, which is intended in production.
        # For testing, we mock this extensively.
        try:
            self.graph = Neo4jGraph(
                url=self.url,
                username=self.username,
                password=self.password
            )
        except Exception as e:
            print(f"Warning: Could not connect to Neo4j at {self.url}. Ensure it is running. Error: {e}")
            self.graph = None

    def ingest_findings(self, raw_findings: List[Dict[str, Any]]) -> None:
        """
        Parses raw findings and maps them as nodes and relationships in Neo4j.
        Schema: Asset -> EXPOSES -> Port -> RUNS -> Service -> HAS -> Vulnerability
        """
        if not self.graph or not raw_findings:
            return

        for finding in raw_findings:
            f_type = finding.get("type")
            target = finding.get("target")

            if not target:
                continue

            # Ensure Asset node exists
            self.graph.query(
                "MERGE (a:Asset {ip: $ip})",
                params={"ip": target}
            )

            if f_type == "service":
                self._map_service(finding)
            elif f_type == "vulnerability":
                self._map_vulnerability(finding)

    def _map_service(self, finding: Dict[str, Any]) -> None:
        """Maps Asset -> Port -> Service relationships."""
        target = finding.get("target")
        port = finding.get("port", "unknown")
        service = finding.get("service", "unknown")
        product = finding.get("product", "")
        version = finding.get("version", "")

        query = """
        MATCH (a:Asset {ip: $ip})
        MERGE (p:Port {port_id: $port})
        MERGE (s:Service {name: $service})
        SET s.product = $product, s.version = $version
        MERGE (a)-[:EXPOSES]->(p)
        MERGE (p)-[:RUNS]->(s)
        """
        self.graph.query(query, params={
            "ip": target,
            "port": port,
            "service": service,
            "product": product,
            "version": version
        })

    def _map_vulnerability(self, finding: Dict[str, Any]) -> None:
        """Maps Asset -> Vulnerability relationships (and optionally links to Services)."""
        target = finding.get("target")
        name = finding.get("name", "Unknown")
        cves = finding.get("cves", [])
        primary_cve = cves[0] if cves else "N/A"
        severity = finding.get("severity", "info")

        # In a perfect world we know exactly which service has the vuln. 
        # For now, we link Vuln -> Asset, but a more advanced parser could link Vuln -> Service.
        query = """
        MATCH (a:Asset {ip: $ip})
        MERGE (v:Vulnerability {name: $name, cve: $cve})
        SET v.severity = $severity
        MERGE (a)-[:HAS_VULNERABILITY]->(v)
        """
        self.graph.query(query, params={
            "ip": target,
            "name": name,
            "cve": primary_cve,
            "severity": severity
        })
