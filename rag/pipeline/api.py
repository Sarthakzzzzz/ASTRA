from rag.pipeline.graph import build_workflow

# The LangGraph API looks for a compiled graph instance
# We build it without Streamlit's session states so the Dev Studio can run it cleanly.
graph = build_workflow()
