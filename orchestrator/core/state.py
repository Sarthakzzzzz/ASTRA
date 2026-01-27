
# Singleton state for the orchestrator
latest_reasoning = "Waiting for active scan analysis..."

def update_reasoning(text: str):
    global latest_reasoning
    latest_reasoning = text

def get_reasoning() -> str:
    return latest_reasoning
