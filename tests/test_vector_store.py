import pytest
import shutil
from unittest.mock import patch, MagicMock
from langchain_core.documents import Document
from rag.threat_intel.database.chroma_store import VulnerabilityVectorStore

@pytest.fixture
def mock_embeddings():
    with patch("rag.threat_intel.database.chroma_store.HuggingFaceEmbeddings") as mock:
        yield mock

@pytest.fixture
def temp_chroma_dir(tmp_path):
    d = tmp_path / "chromadb_test"
    d.mkdir()
    yield str(d)
    # Cleanup after test natively handled by tmp_path, but explicitly clear contents
    if d.exists():
         shutil.rmtree(d)

@patch("rag.threat_intel.database.chroma_store.Chroma")
def test_vector_store_initialization(mock_chroma, mock_embeddings, temp_chroma_dir):
    store = VulnerabilityVectorStore(persist_directory=temp_chroma_dir)
    assert store.persist_directory == temp_chroma_dir
    mock_chroma.assert_called_once()
    mock_embeddings.assert_called_once()

@patch("rag.threat_intel.database.chroma_store.Chroma")
def test_vector_store_ingest(mock_chroma, mock_embeddings, temp_chroma_dir):
    # Setup mock Chrome instance
    mock_chroma_instance = MagicMock()
    mock_chroma.return_value = mock_chroma_instance
    
    store = VulnerabilityVectorStore(persist_directory=temp_chroma_dir)
    
    docs = [
        Document(page_content="test 1", metadata={"id": 1}),
        Document(page_content="test 2", metadata={"id": 2})
    ]
    
    store.ingest_documents(docs)
    mock_chroma_instance.add_documents.assert_called_once_with(docs)

@patch("rag.threat_intel.database.chroma_store.Chroma")
def test_vector_store_query(mock_chroma, mock_embeddings, temp_chroma_dir):
    mock_chroma_instance = MagicMock()
    # Mock search to return one dummy doc
    mock_chroma_instance.similarity_search.return_value = [Document(page_content="found")]
    mock_chroma.return_value = mock_chroma_instance
    
    store = VulnerabilityVectorStore(persist_directory=temp_chroma_dir)
    
    results = store.query("test query", k=1)
    
    assert len(results) == 1
    assert results[0].page_content == "found"
    mock_chroma_instance.similarity_search.assert_called_once_with("test query", k=1)
