
import os
import sys
import threading
import queue
import asyncio
import secrets
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Add the ASTRA root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.core import engine, utils
from orchestrator.core.graph import graph_db

app = FastAPI(
    title="ASTRA API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
API_TOKEN = os.getenv("ASTRA_API_TOKEN", "")


def require_api_token(x_astra_token: Optional[str] = Header(default=None)):
    if not API_TOKEN or not x_astra_token or not secrets.compare_digest(x_astra_token, API_TOKEN):
        raise HTTPException(status_code=401, detail="Valid ASTRA API token required")

# Global log queue for streaming
log_queue = queue.Queue()

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:8501")],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    mode: str = "dynamic"
    scanners: Optional[str] = "all"

@app.get("/")
async def root():
    return {"status": "ASTRA Core AI Online"}

@app.get("/graph", dependencies=[Depends(require_api_token)])
async def get_graph():
    """
    Returns the graph in a format compatible with ReactFlow (Bramhastra UI).
    """
    nodes = []
    edges = []
    
    # Simple mapping of NetworkX nodes to ReactFlow nodes
    for node_id in graph_db.g.nodes:
        data = graph_db.g.nodes[node_id]
        node_type = data.get("type", "unknown")
        
        # Determine styling based on type
        bg_color = "#22d3ee" # Default Cyan
        if node_type == "finding": bg_color = "#f59e0b" # Orange
        if node_type == "impact": bg_color = "#ef4444" # Red
        
        nodes.append({
            "id": str(node_id),
            "data": { "label": data.get("label", node_id) },
            "position": { "x": 100, "y": 100 }, # Placeholder position
            "className": f"glass p-4 text-[10px] border-[{bg_color}]"
        })
        
    for source, target, data in graph_db.g.edges(data=True):
        edges.append({
            "id": f"e-{source}-{target}",
            "source": str(source),
            "target": str(target),
            "animated": True,
            "style": { "stroke": "#22d3ee" }
        })
        
    return { "nodes": nodes, "edges": edges }

def run_scan_in_background(target: str, mode: str, scanners: str):
    """
    Triggers the orchestrator engine and pushes logs to queue.
    """
    log_msg = f"[SERVER] Starting {mode} scan on {target}...\n"
    print(log_msg, end="")
    log_queue.put(log_msg)
    
    for line in engine.run_orchestrator(
        primary_target=target,
        enable_arg=scanners,
        concurrency=5,
        mode=mode,
        dry_run=False
    ):
        if isinstance(line, str):
            print(line, end="")
            log_queue.put(line)

async def event_generator():
    """Generator for SSE to stream log messages."""
    while True:
        try:
            # Non-blocking get with timeout
            message = log_queue.get(timeout=1.0)
            yield f"data: {message}\n\n"
        except queue.Empty:
            # Send keepalive
            yield f": keepalive\n\n"
            await asyncio.sleep(0.5)

@app.get("/api/scan/stream", dependencies=[Depends(require_api_token)])
async def stream_logs():
    """
    Server-Sent Events endpoint for streaming scan logs.
    """
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

@app.post("/api/scan", dependencies=[Depends(require_api_token)])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiates a security scan.
    """
    if not utils.is_valid_target(request.target):
        return {"error": "Invalid target format"}
    
    background_tasks.add_task(run_scan_in_background, request.target, request.mode, request.scanners)
    return {"message": f"Scan initiated on {request.target}"}

# --- AI Integration ---
from google_adk.agent import ScanAgent
# Initialize agent lazily or globally
ai_agent = ScanAgent()

class ChatRequest(BaseModel):
    logs: List[str]
    question: str

@app.post("/ai/explain", dependencies=[Depends(require_api_token)])
async def ai_explain(request: ChatRequest):
    """
    Endpoint for the AI Chat interface to explain logs or answer questions.
    """
    logs_context = "\n".join(request.logs)
    answer = await ai_agent.answer_question_async(logs_context, request.question)
    return {"answer": answer}

@app.get("/ai/reasoning", dependencies=[Depends(require_api_token)])
async def get_reasoning():
    from orchestrator.core import state
    return {"reasoning": state.get_reasoning()}

@app.get("/api/scanners", dependencies=[Depends(require_api_token)])
async def get_scanners():
    from orchestrator.core import registry
    return [
        {"name": sc["name"], "enabled": sc["enabled"]}
        for sc in registry.SCANNERS
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
