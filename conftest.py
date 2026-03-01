"""
Root conftest.py — ensures the ASTRA project root is on sys.path so that
`import rag`, `import orchestrator` etc. work from any test subdirectory.
"""
import sys
import os

# Add the project root (the directory containing this conftest.py) to sys.path
sys.path.insert(0, os.path.dirname(__file__))
