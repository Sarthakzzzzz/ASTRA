# ASTRA - AI-Powered Vulnerability Orchestrator

**ASTRA** is an AI-powered, adaptive vulnerability scanning orchestrator designed to automate and enhance the security testing process. It intelligently chains security tools, adapts its strategy based on real-time findings, and uses a Gemini-powered AI agent to reason about vulnerabilities and recommend next steps.

---



---

It features a futuristic, real-time **Next.js** dashboard and supports two distinct scanning modes:

- **Dynamic Mode**: Leverages an AI Planning Agent to analyze findings and intelligently decide which tools to run next. It adapts its attack strategy in real-time based on discovered assets and vulnerabilities.
- **Static Mode**: Executes a predictable, user-defined sequence of security tools.

---

## 🚀 Key Features

### 🧠 Reasoning Engine & AI Planning
- **Incremental Reasoning**: The AI engine analyzes findings *as they arrive* (Real-time), ensuring the dashboard reflects the current security posture instantly.
- **Adaptive Strategy**: Intelligently chains tools based on open ports, identified services, and discovered vulnerabilities.
- **Strategic Insight**: The "Reasoning Engine" panel displays the AI's high-level thoughts, explaining *why* it chose a specific path.

### 🕸️ Interactive Attack Graph
- **Visual Attack Paths**: Visualizes assets and findings as a dynamic node graph using ReactFlow.
- **Path Analysis**: Automatically traces potential compromise paths from entry points to critical assets.

### 📺 Live Next.js Dashboard
- **Real-time Log Streaming**: Monitor the scan's progress live via Server-Sent Events (SSE).
- **Custom Scanner Selection**: granular control over which tools to run (e.g., specific combinations of `nmap`, `nuclei`, etc.).
- **Live Discovery**: Findings populate the graph and log window instantly.

### ⚡ Concurrent & Modular
- **Concurrent Execution**: Runs multiple tools in parallel for faster and more efficient scanning.
- **Modular Architecture**: Easily extendable with new tools, parsers, and rules.

---

## 🔬 How Dynamic Mode Works

1.  **Initial Scan**: ASTRA begins with a set of baseline enumeration tools (e.g., `nmap`, `whatweb`, `nuclei`).
2.  **Incremental Parsing**: As tools finish, their output is immediately parsed and added to the centralized Graph.
3.  **AI Analysis**: The Google ADK Agent analyzes the new findings.
4.  **Strategic Loop**: 
    -   The agent updates the "Reasoning Engine" display.
    -   It recommends new, targeted scans (e.g., "Found port 80, run `nikto`").
5.  **Execution**: The orchestrator executes the recommended tools automatically.
6.  **Visualization**: The Attack Graph updates in real-time to show the growing network of assets and vulnerabilities.

---

## Directory Structure

```
├── orchestrator
│   ├── core
│   │   ├── engine.py       # Core logic for static/dynamic scanning
│   │   ├── graph.py        # Graph database interface (NetworkX/Neo4j)
│   │   ├── parsers.py      # Tool output parsers
│   │   └── registry.py     # Tool definitions and commands
│   ├── server.py           # FastAPI Backend
│   └── main.py             # CLI Entrypoint
├── frontend                # Next.js Application
│   ├── src
│   │   ├── components      # React Components (Sidebar, ExplainPanel, etc.)
│   │   └── app             # Next.js Pages
├── google_adk              # AI Integration
│   ├── agent.py            # Gemini Agent Logic
│   └── tools.py            # Agent Tool Definitions
└── output                  # Raw Scan Results
```

---

## 🛠️ Tech Stack

-   **Backend**: Python 3.10+ (FastAPI, NetworkX, Google Generative AI)
-   **Frontend**: Next.js 14, React, TailwindCSS, ReactFlow
-   **AI**: Google Gemini 1.5 Flash (via Google ADK)
-   **Graph**: NetworkX (In-memory) / Neo4j (Optional persistence)

---

##  Getting Started (Recommended: Docker)

The easiest way to run ASTRA is with Docker, which automatically installs all security tools and dependencies.

### 1. Prerequisites
-   **Docker** & **Docker Compose**
-   **Google Gemini API Key**: Get it from [Google AI Studio](https://aistudio.google.com/app/apikey).

### 2. Quick Start
1.  Clone the repo:
    ```bash
    git clone https://github.com/Sarthakzzzzz/ASTRA.git
    cd ASTRA
    ```
2.  Configure environment variables:
    ```bash
    # Copy the example and edit with your keys
    cp .env.example .env
    ```
    
    **Required:**
    - `GOOGLE_API_KEY` - Your Google Gemini API key ([Get it here](https://aistudio.google.com/app/apikey))
    
    **Optional:**
    - `NVD_API_KEY` - For enhanced CVE data ([Get it here](https://nvd.nist.gov/developers/request-an-api-key))
    - `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` - For persistent graph storage (defaults to in-memory)
3.  Run with Docker:
    ```bash
    sudo docker compose up --build
    ```

That's it! Access the dashboard at **http://localhost:3000**.

---

## ⚙️ Manual Installation (Advanced)

If you prefer to run locally without Docker (e.g., on Kali Linux natively):

### 1. Install Tools
```bash
sudo apt update && sudo apt install -y nmap whatweb nuclei nikto wpscan joomscan enum4linux sqlmap
```

### 2. Backend Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

### 4. Run
**Terminal 1 (Backend):**
```bash
source .venv/bin/activate
PYTHONPATH=. python orchestrator/server.py
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```