from typing import List
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

class VulnerabilityVectorStore:
    def __init__(self, persist_directory: str = "./chroma_db", model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """Initializes the ChromaDB vector store with HuggingFace embeddings."""
        self.embeddings = HuggingFaceEmbeddings(model_name=model_name)
        self.persist_directory = persist_directory
        self.vector_store = Chroma(
            collection_name="astra_vulnerabilities",
            embedding_function=self.embeddings,
            persist_directory=self.persist_directory
        )

    def ingest_documents(self, documents: List[Document]) -> None:
        """Adds LangChain Document objects to the vector store."""
        if not documents:
            return
            
        # We process in batches if necessary, but Chroma handles small batches well
        self.vector_store.add_documents(documents)
        
    def query(self, query_text: str, k: int = 3) -> List[Document]:
        """Performs a semantic similarity search against the stored vulnerabilities."""
        return self.vector_store.similarity_search(query_text, k=k)
