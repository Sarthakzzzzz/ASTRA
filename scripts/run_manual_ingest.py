import os
import sys
from dotenv import load_dotenv
import streamlit as st

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from streamlit_app import display_scan_results
from rag.research_agent.phase2_database.graph_store import AttackGraphStore

load_dotenv()

TARGET = "scanme.nmap.org"

print(f"Loading previous scan findings for {TARGET}...")

# Mock Streamlit to avoid errors
st.markdown = lambda *args, **kwargs: None
st.header = lambda *args, **kwargs: None
st.warning = lambda *args, **kwargs: None
st.info = lambda *args, **kwargs: None
st.text = lambda *args, **kwargs: None
st.code = lambda *args, **kwargs: None
st.error = lambda *args, **kwargs: None

class MockExpander:
    def __enter__(self): pass
    def __exit__(self, _exc_type, _exc_val, _exc_tb): pass
st.expander = lambda *args, **kwargs: MockExpander()

class MockColumn:
    def __enter__(self): pass
    def __exit__(self, _exc_type, _exc_val, _exc_tb): pass
st.columns = lambda n: [MockColumn() for _ in range(n)]


findings = display_scan_results(TARGET)

if not findings:
    print("No findings were returned from display_scan_results.")
    sys.exit(1)

print(f"Extracted {len(findings)} findings. Sample finding:")
print(findings[0])

print("\nConnecting to Neo4j and ingesting findings...")
try:
    store = AttackGraphStore()
    store.ingest_findings(findings)
    print("✅ Ingestion complete! Check AuraDB.")
except Exception as e:
    print(f"❌ Ingestion failed: {e}")
