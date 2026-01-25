# ASTRA - Vulnerability Orchestrator

**ASTRA** is an intelligent vulnerability scanning orchestrator designed to automate and enhance the security testing process.  
It features a sleek, real-time Streamlit dashboard and supports two distinct scanning modes:

- **Static Mode**: Executes a predictable, repeatable sequence of tools.  
- **Dynamic Mode**: Adapts intelligently as it scans, evolving based on discovered vulnerabilities and assets.

---

## 🚀 Key Features

### 🔁 Dual Scan Modes

- **Static Mode**: Executes a predefined, fixed sequence of security tools. Ideal for consistent, repeatable scans.
- **Dynamic Mode**: Uses a real-time rules engine that adapts the scan strategy based on discovered assets and vulnerabilities.

### 📺 Live Web Dashboard

- Real-time log streaming
- Live discovery of findings
- Interactive configuration panel  
- Built with a clean, dark-themed Streamlit UI

### ⚡ Concurrent Execution

- Runs multiple tools in parallel using thread pools for faster and more efficient orchestration.

### 🧩 Modular & Extensible Architecture

- Clear separation of concerns (`engine`, `parsers`, `runner`, `rules`)
- Easily add new tools, parsers, or dynamic logic.

### 📊 Structured Findings

- Automatically parses and normalizes tool outputs into a standardized format for easy analysis and visualization.

---



## Directory Structure

    ├── orchestrator
    │   ├── core
    │   │   ├── dependencies.py
    │   │   ├── engine.py
    │   │   ├── findings.py
    │   │   ├── parsers.py
    │   │   ├── registry.py
    │   │   ├── rules_engine.py
    │   │   ├── runner.py
    │   │   ├── services.py
    │   │   └── utils.py
    │   ├── logs
    │   ├── main.py
    │   ├── output
    │   │   └── raw
    │   └── rules
    │       ├── network.yaml
    │       ├── vulnerabilities.yaml
    │       └── web.yaml
    └── streamlit_app.py

--- 

## 🏗️ Project Architecture

ASTRA operates on a modular, pipeline-based architecture.


- UI (Streamlit): Captures user input (target, mode) and visualizes live logs and final reports.

- Engine: The central coordinator. It receives the scan request and, depending on the mode, either follows a static plan or consults the Rules Engine.

- Rules Engine: In Dynamic mode, this component compares active findings against its "rulebook" (YAML files) to decide if new scans should be triggered.

- Parsers: Translates the raw text/XML/JSON output from various tools into a standardized StandardFinding object that the engine can understand.

- Runner: Securely executes the command-line tools and streams their output back to the engine.

---

## Tech Stack
- Backend: Python 3.8+

- Frontend: Streamlit

- Configuration: YAML

- Core Libraries: concurrent.futures, pathlib
---

## 🧪 Getting Started

### 1. Prerequisites

ASTRA is a wrapper around popular CLI-based security tools.  
Make sure these tools are installed and available in your system's `PATH`.

For Debian/Ubuntu (e.g., Kali Linux):

```bash
sudo apt update && sudo apt install -y nmap whatweb nuclei wpscan joomscan enum4linux sqlmap python3-pip
```


### 2. Installation
First, clone the repository to your local machine:
```bash
    git clone [https://github.com/DBS01107/ASTRA.git](https://github.com/DBS01107/ASTRA.git)
    cd ASTRA
```


Next, install the required Python libraries:
```bash
    pip install -r requirements.txt
```


### 3. Usage
You can run ASTRA in two ways: via the command line for automation or through the user-friendly web interface.

- Command-Line Interface (CLI)
    Navigate to the project's root directory (ASTRA/) to run the orchestrator.

- Running a Dynamic Scan (Recommended):
```bash
    python3 orchestrator/orchestrator.py scanme.nmap.org --mode dynamic
```
- Running a Static Scan:
```bash
python3 orchestrator/orchestrator.py scanme.nmap.org --mode static --enable nmap,whatweb
```

- Web Dashboard
Launch the Streamlit web application:
```bash
streamlit run streamlit_app.py
```

This will automatically open the ASTRA Dashboard in your web browser.


---


## Project Roadmap
This project is structured to align with the Smart India Hackathon (SIH) problem statement "Centralized Vulnerability Detection and Intelligent Query Interface."

### Phase 1: Intelligent Scanning GUI

- Develop a responsive web GUI (streamlit_app.py).

- Integrate core enumeration tools (Nmap, WhatWeb, Nuclei, etc.).

- Implement an adaptive engine to intelligently chain tools.

- Generate raw, tool-specific output.

### Phase 2: Aggregation & Attack Path Generation

- Develop a reporting module to aggregate all raw outputs into a single, structured report.

- Normalize findings into a consistent format (CVE IDs, CVSS scores).

- Automatically generate the attack path based on the chain of triggered rules from the dynamic scan.

- Enrich findings with data from external threat intelligence sources (NVD, ExploitDB).

### Phase 3: RAG-Based AI Assistant

- Integrate a context-aware RAG chatbot.

- Allow natural language queries on vulnerabilities and attack paths.

- Deliver exploit steps and remediation guidance based on the consolidated report.

