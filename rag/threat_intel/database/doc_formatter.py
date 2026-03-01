from typing import List, Dict, Any
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings

class DocumentProcessor:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """Initializes the local HuggingFace embeddings model."""
        # This will download the model on first run if not present locally
        self.embeddings = HuggingFaceEmbeddings(model_name=model_name)

    def process_findings(self, enriched_findings: List[Dict[str, Any]]) -> List[Document]:
        """Converts enriched findings dictionaries into LangChain Document objects."""
        documents = []
        for finding in enriched_findings:
            page_content = self._create_page_content(finding)
            metadata = self._create_metadata(finding)
            
            doc = Document(page_content=page_content, metadata=metadata)
            documents.append(doc)
            
        return documents

    def _create_page_content(self, finding: Dict[str, Any]) -> str:
        """Synthesizes a readable summary from the finding data."""
        finding_type = finding.get("type", "unknown")
        
        if finding_type == "vulnerability":
            cves = ", ".join(finding.get("cves", []))
            desc = finding.get("description", "No description provided.")
            name = finding.get("name", "Unknown Vulnerability")
            target = finding.get("target", "Unknown Target")
            
            # Context formatting
            content = f"Vulnerability finding on target {target}.\n"
            content += f"Name: {name}\n"
            content += f"CVEs: {cves}\n"
            content += f"Description: {desc}\n"
            
            # If NVD details were merged in by the orchestrator/extractor
            if "nvd_details" in finding:
                nvd = finding["nvd_details"]
                if "error" not in nvd:
                    content += f"\nNVD Severity: {nvd.get('severity')}\n"
                    content += f"NVD CVSS Score: {nvd.get('cvss_score')}\n"
                    content += f"NVD Full Description: {nvd.get('description')}\n"
            
            # If Tavily exploit context was merged in
            if "exploit_context" in finding:
                content += f"\nExploit Context (Web Search):\n{finding.get('exploit_context')}\n"
                
            return content

        elif finding_type == "service":
            target = finding.get("target", "Unknown Target")
            port = finding.get("port", "Unknown Port")
            service = finding.get("service", "Unknown Service")
            version = finding.get("version", "")
            product = finding.get("product", "")
            
            content = f"Service/Port finding on target {target}.\n"
            content += f"Port: {port}\n"
            content += f"Service Protocol: {service}\n"
            if product or version:
                content += f"Running Software: {product} {version}\n"
                
            return content
            
        else:
            return f"Generic finding: {finding.get('name', 'Unknown')}\nDetails: {finding}"

    def _create_metadata(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts structured metadata for filtering in vector stores."""
        metadata = {
            "target": finding.get("target", "unknown"),
            "finding_type": finding.get("type", "unknown"),
        }
        
        if finding.get("type") == "vulnerability":
            metadata["severity"] = finding.get("severity", "info")
            if finding.get("cves"):
                # Store primary CVE for easy filtering
                metadata["primary_cve"] = finding["cves"][0]
                
        elif finding.get("type") == "service":
            metadata["port"] = finding.get("port", "unknown")
            metadata["service"] = finding.get("service", "unknown")
            
        return metadata

    def embed_documents(self, documents: List[Document]) -> List[List[float]]:
        """Utility to verify embedding generation (usually handled directly by VectorStores)."""
        texts = [doc.page_content for doc in documents]
        return self.embeddings.embed_documents(texts)
