# ASTRA - AI-Powered Vulnerability Orchestrator

**ASTRA** is an AI-powered, adaptive vulnerability scanning orchestrator designed to automate and enhance the security testing process. It intelligently chains security tools, adapts its strategy based on real-time findings, and uses a Gemini-powered AI agent to reason about vulnerabilities and recommend next steps.

---

## 🌐 Live Demo

A live demo of the ASTRA dashboard is available here:

**[https://d97dfd578485.ngrok-free.app/](https://d97dfd578485.ngrok-free.app/)**

---

It features a sleek, real-time Streamlit dashboard and supports two distinct scanning modes:

- **Dynamic Mode**: Leverages an AI Planning Agent to analyze findings and intelligently decide which tools to run next. It adapts its attack strategy in real-time based on discovered assets and vulnerabilities.
- **Static Mode**: Executes a predictable, user-defined sequence of security tools.

---

## 🚀 Key Features

### 🧠 AI-Powered Dynamic Scanning
- **AI Planning Agent**: Uses the Gemini 1.5 Flash API to analyze initial scan results and create a dynamic attack plan.
- **Adaptive Strategy**: Intelligently chains tools based on open ports, identified services, and discovered vulnerabilities.
- **Finding Enrichment**: Automatically enriches findings with risk levels and capabilities to inform the AI's decision-making process.
- **ExploitDB Integration**: Searches ExploitDB for known exploits related to discovered services to prioritize high-risk targets.

### 📺 Live Web Dashboard
- **Real-time Log Streaming**: Monitor the scan's progress live.
- **Live Discovery of Findings**: See vulnerabilities and results as they are found.
- **Interactive Configuration**: Easily configure and launch scans from a user-friendly UI.
- **Built with Streamlit**: A clean, modern, and responsive interface.

### ⚡ Concurrent & Modular
- **Concurrent Execution**: Runs multiple tools in parallel for faster and more efficient scanning.
- **Modular Architecture**: Easily extendable with new tools, parsers, and rules.

---

## 🔬 How Dynamic Mode Works

1.  **Initial Scan**: ASTRA begins with a set of baseline enumeration tools (e.g., `nmap`, `whatweb`, `nuclei`).
2.  **Finding Enrichment**: The raw output from these tools is parsed into a structured format and enriched with metadata, such as risk level and capability (e.g., `web_server`, `database_server`).
3.  **AI Analysis**: The enriched findings are sent to the Gemini-powered AI Planning Agent.
4.  **Tool Recommendation**: The AI agent analyzes the findings, reasons about potential attack vectors, and recommends the next best tools to run from its registry.
5.  **Iterative Scanning**: ASTRA executes the recommended tools, collects the new findings, and repeats the cycle.
6.  **Completion**: The scan concludes when the AI agent no longer recommends new tools, or the maximum number of iterations is reached.

---

## Directory Structure

```
├── orchestrator
│   ├── core
│   │   ├── ai
│   │   │   ├── attack_path.py
│   │   │   ├── client.py
│   │   │   ├── exploitdb.py
│   │   │   └── planning_agent.py
│   │   ├── extractors
│   │   ├── __init__.py
│   │   ├── ai_agent.py
│   │   ├── capabilities.py
│   │   ├── dependencies.py
│   │   ├── engine.py
│   │   ├── findings.py
│   │   ├── graph.py
│   │   ├── parsers.py
│   │   ├── planner.py
│   │   ├── registry.py
│   │   ├── rules_engine.py
│   │   ├── rules_loader.py
│   │   ├── runner.py
│   │   └── utils.py
│   ├── __init__.py
│   ├── main.py
│   └── rules
│       ├── auth.yaml
│       ├── database.yaml
│       ├── network.yaml
│       ├── vulnerabilities.yaml
│       └── web.yaml
├── requirements.txt
└── streamlit_app.py
```

---

## 🛠️ Tech Stack

-   **Backend**: Python 3.8+
-   **AI**: Google Gemini 1.5 Flash
-   **Frontend**: Streamlit
-   **Configuration**: YAML
-   **Core Libraries**: `google-generativeai`, `concurrent.futures`, `pathlib`

---

## 🧪 Getting Started

### 1. Prerequisites

ASTRA requires a Google Gemini API key and a set of common security tools.

**A. Configure Gemini API Key:**

1.  Obtain an API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2.  Create a `.env` file in the root of the project.
3.  Add your API key to the `.env` file:
    ```
    GEMINI_API_KEY=your_api_key_here
    ```

**B. Install Required Tools:**

ASTRA is a wrapper around popular CLI-based security tools. Make sure these tools are installed and available in your system's `PATH`.

For Debian/Ubuntu (e.g., Kali Linux):
```bash
sudo apt update && sudo apt install -y nmap whatweb nuclei nikto wpscan joomscan enum4linux sqlmap
```

### 2. Installation

First, clone the repository and install the required Python libraries:

```bash
git clone https://github.com/Sarthakzzzzz/ASTRA.git
cd ASTRA
pip install -r requirements.txt
```

### 3. Usage

You can run ASTRA via the command line or through the user-friendly web interface.

#### Command-Line Interface (CLI)

Run a **dynamic scan** (recommended):
```bash
python3 orchestrator/main.py scanme.nmap.org --mode dynamic
```

Run a **static scan** with specific tools:
```bash
python3 orchestrator/main.py scanme.nmap.org --mode static --enable nmap,whatweb,nikto
```

#### Web Dashboard

Launch the Streamlit web application:
```bash
streamlit run streamlit_app.py
```
This will open the ASTRA Dashboard in your web browser, where you can configure and run scans interactively.