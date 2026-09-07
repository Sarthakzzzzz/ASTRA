import streamlit as st
import requests
import hmac

import os


def get_setting(name, default=""):
    try:
        return st.secrets.get(name, os.getenv(name, default))
    except Exception:
        return os.getenv(name, default)


BACKEND = get_setting("BACKEND_URL", "http://localhost:8000")
BACKEND_TOKEN = get_setting("ASTRA_API_TOKEN")
HEADERS = {"X-ASTRA-Token": BACKEND_TOKEN} if BACKEND_TOKEN else {}
APP_PASSWORD = get_setting("APP_PASSWORD")

st.set_page_config(page_title="ASTRA", layout="wide", page_icon="🛡️")

if not APP_PASSWORD:
    st.error("APP_PASSWORD is not configured. The application is locked.")
    st.stop()

if not st.session_state.get("authenticated", False):
    st.title("ASTRA")
    password = st.text_input("Password", type="password")
    if st.button("Sign in"):
        if hmac.compare_digest(password, APP_PASSWORD):
            st.session_state.authenticated = True
            st.rerun()
        st.error("Invalid password")
    st.stop()

st.markdown("""
<style>
body, .stApp { background-color: #02030a; color: #eaeaf0; }
.stTextInput input, .stSelectbox select {
    background-color: #0a0b14 !important;
    color: #eaeaf0 !important;
    border: 1px solid rgba(34,211,238,0.3) !important;
}
.stButton > button {
    background: transparent;
    border: 1px solid #22d3ee;
    color: #22d3ee;
    font-weight: bold;
    letter-spacing: 0.15em;
    width: 100%;
}
.stButton > button:hover { background: #22d3ee; color: #000; }
.terminal-box {
    background: #000;
    border: 1px solid rgba(34,211,238,0.2);
    padding: 12px;
    font-family: monospace;
    font-size: 11px;
    height: 300px;
    overflow-y: auto;
    color: #4ade80;
}
.reasoning-box {
    background: rgba(8,47,73,0.3);
    border: 1px solid rgba(34,211,238,0.15);
    padding: 12px;
    font-family: monospace;
    font-size: 12px;
    color: #cffafe;
    min-height: 120px;
}
.badge-critical { color: #ef4444; font-weight: bold; }
.badge-high     { color: #f97316; font-weight: bold; }
.badge-medium   { color: #f59e0b; }
.badge-low      { color: #22d3ee; }
h1, h2, h3 { color: #22d3ee !important; }
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
for key, default in [("logs", []), ("scanning", False), ("graph_data", None)]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── Helpers ────────────────────────────────────────────────────────────────────
def fetch_scanners():
    try:
        return [s["name"] for s in requests.get(f"{BACKEND}/api/scanners", headers=HEADERS, timeout=3).json()]
    except Exception:
        return ["nmap", "nuclei", "whatweb", "nikto"]

def fetch_graph():
    try:
        return requests.get(f"{BACKEND}/graph", headers=HEADERS, timeout=3).json()
    except Exception:
        return None

def fetch_reasoning():
    try:
        return requests.get(f"{BACKEND}/ai/reasoning", headers=HEADERS, timeout=3).json().get("reasoning", "")
    except Exception:
        return ""

def start_scan(target, mode, scanners):
    try:
        res = requests.post(f"{BACKEND}/api/scan", headers=HEADERS, json={
            "target": target,
            "mode": mode,
            "scanners": ",".join(scanners)
        }, timeout=5)
        return res.json().get("message", "Scan initiated.")
    except Exception as e:
        return f"Error: {e}"

def stream_logs():
    """Pull logs from SSE endpoint and append to session state."""
    try:
        with requests.get(f"{BACKEND}/api/scan/stream", headers=HEADERS, stream=True, timeout=60) as r:
            for raw in r.iter_lines():
                if raw and raw.startswith(b"data:"):
                    line = raw[5:].decode().strip()
                    if line:
                        st.session_state.logs.append(line)
                        yield line
    except Exception:
        pass

# ── Layout ─────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ ASTRA — AI Vulnerability Orchestrator")

sidebar, main_col, ai_col = st.columns([1, 2.2, 1.2])

# ── Sidebar ────────────────────────────────────────────────────────────────────
with sidebar:
    st.markdown("### ⚙️ Config")
    target = st.text_input("Target", placeholder="scanme.nmap.org")
    mode = st.radio("Mode", ["dynamic", "static"], horizontal=True)

    all_scanners = fetch_scanners()
    selected = st.multiselect("Modules", all_scanners, default=all_scanners)

    st.caption(f"Modules selected: **{len(selected)}**")

    if st.button("▶ EXECUTE SCAN", disabled=not target or not selected):
        st.session_state.logs = []
        st.session_state.scanning = True
        msg = start_scan(target, mode, selected)
        st.success(msg)

    if st.session_state.scanning and st.button("⏹ Stop Streaming"):
        st.session_state.scanning = False

# ── Main column: Terminal + Graph ──────────────────────────────────────────────
with main_col:
    st.markdown("### 📺 Live Scan Output")

    log_placeholder = st.empty()

    def render_terminal():
        lines = st.session_state.logs[-100:]  # last 100 lines
        html = "<br>".join(line.replace("<", "&lt;") for line in lines) or \
               "<span style='color:#22d3ee44;font-style:italic'>Waiting for scan...</span>"
        log_placeholder.markdown(f'<div class="terminal-box">{html}</div>', unsafe_allow_html=True)

    render_terminal()

    # Stream logs if scanning
    if st.session_state.scanning:
        for _ in stream_logs():
            render_terminal()
        st.session_state.scanning = False

    # ── Attack Graph ───────────────────────────────────────────────────────────
    st.markdown("### 🕸️ Attack Graph")
    graph_data = fetch_graph()

    if graph_data and graph_data.get("nodes"):
        import pandas as pd

        nodes = graph_data["nodes"]
        edges = graph_data["edges"]

        node_map = {n["id"]: n["data"]["label"] for n in nodes}

        # Show nodes as a table
        node_rows = [{"ID": n["id"], "Label": n["data"]["label"]} for n in nodes]
        st.dataframe(pd.DataFrame(node_rows), use_container_width=True, hide_index=True)

        if edges:
            edge_rows = [{"From": node_map.get(e["source"], e["source"]),
                          "To":   node_map.get(e["target"], e["target"])} for e in edges]
            st.markdown("**Edges**")
            st.dataframe(pd.DataFrame(edge_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No graph data yet. Start a scan to populate the attack graph.")

# ── AI Panel ───────────────────────────────────────────────────────────────────
with ai_col:
    st.markdown("### 🧠 Reasoning Engine")
    reasoning = fetch_reasoning()
    st.markdown(
        f'<div class="reasoning-box">{reasoning or "Waiting for active scan analysis..."}</div>',
        unsafe_allow_html=True
    )

    if st.button("🔄 Refresh Reasoning"):
        st.rerun()

    st.markdown("### 💬 AI Chat")
    question = st.text_input("Ask about findings...", key="chat_q")

    if st.button("Ask") and question:
        try:
            res = requests.post(f"{BACKEND}/ai/explain", json={
                "logs": st.session_state.logs[-20:],
                "question": question
            }, timeout=30)
            answer = res.json().get("answer", "No response.")
        except Exception as e:
            answer = f"Error: {e}"

        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []
        st.session_state.chat_history.append(("You", question))
        st.session_state.chat_history.append(("AI", answer))

    if "chat_history" in st.session_state:
        for role, msg in st.session_state.chat_history[-10:]:
            prefix = "🧑" if role == "You" else "🤖"
            st.markdown(f"**{prefix} {role}:** {msg}")

# ── Auto-refresh graph every 5s when scanning ──────────────────────────────────
if st.session_state.scanning:
    time.sleep(5)
    st.rerun()
