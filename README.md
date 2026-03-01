# ASTRA — AI-Powered Vulnerability Scanning Orchestrator

**ASTRA** is an adaptive, AI-driven vulnerability scanning orchestrator. It intelligently chains security tools, reasons about findings in real time using **Gemini 2.5 Flash Lite**, and converges on an attack surface through iterative scanning — without human intervention.

---

## ✨ Key Features

### 🧠 Dynamic Mode — AI-Adaptive Scanning
- **AI Decision Agent** powered by Gemini 2.5 Flash Lite analyzes findings after each iteration
- Dynamically selects the next tools to run based on discovered ports, services, and CVEs
- Iterates until no new attack surfaces are found (convergence-based termination)
- All reasoning and tool decisions are logged as a structured **AI Decision Summary**

### ⚡ Static Mode — Deterministic Scanning
- User selects a fixed toolset; ASTRA runs them in a defined sequence
- Fully predictable and auditable — no AI involvement
- Ideal for compliance scans and reproducible results

### 🔗 Concurrent Execution
- AI-recommended tools are dispatched concurrently via `ThreadPoolExecutor`
- Per-tool timeouts prevent any single tool from blocking the pipeline
- Baseline tools (nmap, whatweb, nuclei) always run in the initial iteration

### 🧬 RAG Knowledge Base
- ChromaDB-backed vector store ingested with CVE advisories and threat intel
- AI agent queries the RAG store before making tool recommendations
- Enriches findings with contextual vulnerability descriptions

### 🗺️ Attack Path Generation
- Generates a DOT graph (`*.dot`) visualizing the inferred attack chain
- Nodes: target host → services → CVEs / misconfigurations
- Parseable by Graphviz or importable into graph tools

---

## 🏗️ Architecture

```
ASTRA/
├── orchestrator/
│   ├── cli.py                     # Entry point
│   ├── kernel/
│   │   ├── orchestrator_engine.py # Main scan loop (iteration control)
│   │   ├── tool_executor.py       # Concurrent tool dispatch + timeout
│   │   ├── scanner_registry.py    # Tool definitions, commands, dependencies
│   │   ├── rule_interpreter.py    # YAML rule loader and matcher
│   │   └── brain/
│   │       ├── decision_agent.py  # Gemini AI — tool recommendation node
│   │       └── llm_client.py      # Gemini 2.5 Flash Lite client wrapper
│   ├── core/
│   │   ├── registry.py            # Scanner capability registry
│   │   ├── findings.py            # Structured finding model
│   │   ├── parsers.py             # Tool output parsers (nmap XML, WhatWeb JSON…)
│   │   └── ai/
│   │       ├── planning_agent.py  # LangGraph planning node
│   │       ├── attack_path.py     # DOT graph generator
│   │       └── exploitdb.py       # ExploitDB search integration
│   └── rules/                     # YAML rule definitions
│       ├── auth.yaml
│       ├── database.yaml
│       ├── network.yaml
│       ├── vulnerabilities.yaml
│       └── web.yaml
├── rag/
│   ├── attack_chain/
│   │   └── path_generator.py      # LangChain attack path generator
│   ├── threat_intel/
│   │   └── search/                # ChromaDB retrieval & result ranker
│   └── research_agent/
│       └── phase3_retrieval/      # RAG retrieval pipeline
├── scripts/
│   └── run_manual_ingest.py       # Manually ingest CVE docs into ChromaDB
├── tests/
├── requirements.txt
├── pyproject.toml
└── .env                           # API keys (not committed — see .env.example)
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **AI Model** | Gemini 2.5 Flash Lite (`google-generativeai`) |
| **Orchestration** | LangGraph + LangChain |
| **Vector Store** | ChromaDB |
| **Concurrency** | `ThreadPoolExecutor` |
| **Config** | YAML rules + `.env` |
| **Scanners** | nmap, nuclei, whatweb, nikto, wpscan, sqlmap, enum4linux, vulners |

---

## 🚀 Getting Started

### 1. Prerequisites

**A. Configure API Keys**

```bash
cp .env.example .env
# Edit .env and fill in your keys (see .env.example for all required variables)
```

Get a Gemini key at [Google AI Studio](https://aistudio.google.com/app/apikey).

**B. Install Security Tools**

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y nmap whatweb nikto wpscan sqlmap enum4linux graphviz

# nuclei (Go-based)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Ingest RAG Knowledge Base

```bash
python3 scripts/run_manual_ingest.py
```

### 4. Run a Scan

**Dynamic Mode** (AI-adaptive, recommended):
```bash
python3 orchestrator/cli.py scanme.nmap.org --mode dynamic
```

**Static Mode** (fixed toolset):
```bash
python3 orchestrator/cli.py scanme.nmap.org --mode static --enable nmap,whatweb,nikto,nuclei
```

**Options:**
```
positional arguments:
  target              Target IP, domain, or URL

options:
  --mode {static,dynamic}   Scanning mode (default: static)
  --enable TOOLS            Comma-separated tool list, or 'all'
  --concurrency N           Max concurrent tools (default: 5)
  --dry-run                 Print commands without executing
```

---

## 🔬 How Dynamic Mode Works

```
Target
  │
  ▼
[Iteration 1] nmap + whatweb + nuclei  (baseline)
  │
  ├─ Findings parsed + enriched with risk metadata
  │
  ▼
[Gemini AI Decision Agent]
  │  Queries RAG (ChromaDB) for CVE context
  │  Reasons about open ports + services
  │  Recommends next tools (e.g. nikto, vulners, wpscan)
  │
  ▼
[Iteration 2] Run AI-recommended tools concurrently
  │
  ▼
[Gemini AI] — no new tools needed → SCAN COMPLETE
  │
  ▼
Attack Path DOT graph generated → orchestrator/results/<target>_attack_path.dot
```

---

## 📄 Output

| File | Description |
|---|---|
| `orchestrator/results/raw/<target>_nmap.xml` | Nmap XML output |
| `orchestrator/results/raw/<target>_whatweb.json` | WhatWeb JSON |
| `orchestrator/results/<target>_attack_path.dot` | Attack path DOT graph |
| `orchestrator/results/<target>_findings.json` | Consolidated findings |

---

## ⚠️ Legal Disclaimer

ASTRA is intended for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.