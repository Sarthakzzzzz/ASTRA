import streamlit as st
import sys
import os
from pathlib import Path

# --- Path Setup ---
# This is crucial for Streamlit to find your 'orchestrator' module.
# It adds the current directory (where you run `streamlit run ...`) to Python's path.
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    # Import all the necessary components from your backend
    from orchestrator.kernel import orchestrator_engine as engine
    from orchestrator.kernel import helpers as utils
    from orchestrator.kernel import scanner_resolver as dependencies
    from rag.pipeline.graph import build_workflow
    from rag.pipeline.state import GraphState
except ImportError as e:
    st.error(f"""
    **Fatal Error:** Could not import the orchestrator module.
    Please ensure that:
    1. This `streamlit_app.py` file is in your project's root directory (`ASTRA/`).
    2. The orchestrator code is inside an `orchestrator/` subdirectory.

    **Error details:** {e}
    """)
    st.stop()

# --- Configuration ---
OUTPUT_DIR = Path("orchestrator/results/raw")

# --- UI Helper Functions ---

def display_scan_results(primary_target: str) -> list:
    """
    Finds and displays formatted results from output files in expanders.
    Returns the raw parsed dictionaries of the findings for the RAG workflow.
    """
    st.markdown("---")
    st.header("📊 Scan Results")

    sanitized_target = utils.sanitize_target(primary_target)
    findings_for_workflow = []
    
    try:
        # A more robust way to find all files related to this specific scan target
        result_files = sorted([
            f for f in OUTPUT_DIR.iterdir()
            if sanitized_target in f.name
        ])
    except FileNotFoundError:
        st.warning("Output directory not found. A scan must be run to generate results.")
        return []

    if not result_files:
        st.info("No result files found for this target. The scan may have failed or produced no output.")
        return []

    # Create columns for a cleaner layout
    col1, col2 = st.columns(2)

    for i, file_path in enumerate(result_files):
        # Distribute expanders between the two columns
        container = col1 if i % 2 == 0 else col2

        with container:
            with st.expander(f"📄 **{file_path.name}**", expanded=False):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    if content.strip():
                        # Use appropriate language for highlighting
                        lang = "json" if file_path.suffix in [".json", ".jsonl"] else "xml" if file_path.suffix == ".xml" else "log"
                        st.code(content, language=lang, line_numbers=True)
                        
                        # Very simple mock conversion of raw file string to finding dictionaries for the RAG demo
                        # In production, you'd use the actual parsing logic from the parsers module.
                        findings_for_workflow.append({
                            "type": "vulnerability" if "nuclei" in file_path.name else "service",
                            "source": file_path.name,
                            "target": primary_target,
                            "port": "80" if "nuclei" in file_path.name else "443",
                            "service": "http" if "nuclei" in file_path.name else "https",
                            "product": "Apache" if "nuclei" in file_path.name else "Nginx",
                            "version": "2.4.49",
                            "cves": ["CVE-2021-44228"] if "nuclei" in file_path.name else [] # Mock CVE injection
                        })
                    else:
                        st.text("File is empty.")
                except Exception as e:
                    st.error(f"Could not read or display file: {e}")
                    
    return findings_for_workflow




# --- Main Application Logic ---

def main():
    st.set_page_config(
        page_title="ASTRA Vulnerability Orchestrator",
        page_icon="🛡️",
        layout="wide"
    )

    # --- Sidebar for Scan Configuration ---
    with st.sidebar:
        st.image("https://img.icons8.com/external-flaticons-flat-flat-icons/100/external-security-cyber-security-flaticons-flat-flat-icons.png", width=100)
        st.title("ASTRA Orchestrator")
        st.markdown("Centralized Vulnerability Detection")
        st.markdown("---")

        target = st.text_input(
            "🎯 **Target**",
            placeholder="e.g., scanme.nmap.org",
            help="Enter a domain, IP address, or URL."
        )

        # --- NEW: MODE SELECTOR ---
        scan_mode_selection = st.radio(
            "🧠 **Scan Mode**",
            ['Dynamic (Recommended)', 'Static'],
            index=0,
            horizontal=True,
            help="**Dynamic:** Engine intelligently triggers scans based on findings. **Static:** Runs only the specific tools you select."
        )
        # Convert selection to the value the engine expects ('dynamic' or 'static')
        scan_mode = 'dynamic' if scan_mode_selection == 'Dynamic (Recommended)' else 'static'

        # --- NEW: CONDITIONAL UI FOR SCANNER SELECTION ---
        enabled_scanners = []
        if scan_mode == 'static':
            available_scanners = [sc['name'] for sc in dependencies.registry.SCANNERS]
            enabled_scanners = st.multiselect(
                "🛠️ **Select Scanners**",
                options=available_scanners,
                default=["nmap", "whatweb"],
                help="Choose the specific tools you want to run in Static mode."
            )
        else: # Dynamic mode
            st.info("🤖 **Dynamic Mode:** AI-powered adaptive scanning with ExploitDB integration")
            st.markdown("- Automatically searches ExploitDB for discovered services")
            st.markdown("- Intelligently chains tools based on findings")
            st.markdown("- Uses rules engine for targeted exploitation")
            # In dynamic mode, we provide a base set of tools to start the chain reaction.
            enabled_scanners = ["nmap", "whatweb", "nuclei"]

        with st.expander("Advanced Options"):
            concurrency = st.slider(
                "⚡ **Concurrency**",
                min_value=1, max_value=10, value=4,
                help="How many tools to run in parallel within a group."
            )

        st.markdown("---")
        # Disable button if no target is entered
        start_scan_button = st.button("🚀 Launch Scan", use_container_width=True, type="primary", disabled=(not target))

    # --- Main Content Area ---
    st.title("🛡️ ASTRA Vulnerability Dashboard")

    if not target:
        st.info("Please enter a target in the sidebar to begin.")
        st.stop()

    st.markdown(f"**Target:** `{target}` | **Mode:** `{scan_mode.capitalize()}` | **Concurrency:** `{concurrency}`")

    # --- State Management ---
    if "workflow_memory" not in st.session_state:
        from langgraph.checkpoint.memory import MemorySaver
        st.session_state.workflow_memory = MemorySaver()
    
    if "scan_completed" not in st.session_state:
        st.session_state.scan_completed = False
        
    # --- Scan Execution and Live Log Display ---
    if start_scan_button:
        if not utils.is_valid_target(target):
            st.error("❌ Invalid target format. Please enter a valid IP, domain, or URL.")
            return
        if not enabled_scanners:
            st.warning("⚠️ No scanners selected. Please choose at least one tool for Static mode.")
            return

        st.markdown("---")
        st.header("🔴 Live Log")

        log_container = st.empty()
        log_content = ""

        try:
            with st.spinner("Initializing scan..."):
                scan_generator = engine.run_orchestrator(
                    primary_target=target,
                    mode=scan_mode, 
                    enable_arg=",".join(enabled_scanners),
                    concurrency=concurrency,
                    dry_run=False
                )

            for line in scan_generator:
                log_content += line
                log_container.code(log_content, language="log")

            st.success("✅ Scan completed!")
            st.session_state.scan_completed = True
            st.session_state.scan_target = target
            st.session_state.attack_path_generated = False # Reset for new scan

        except Exception as e:
            st.error(f"A critical error occurred during the scan: {e}")
            log_container.code(log_content, language="log") 

    # --- Post-Scan RAG Workflow & UI ---
    if st.session_state.get("scan_completed"):
        current_target = st.session_state.get("scan_target", target)
        findings_for_workflow = display_scan_results(current_target)
        
        if findings_for_workflow:
            st.markdown("---")
            st.header("🧠 Phase 1: Research & Recommendations (RAG)")
            
            thread_config = {"configurable": {"thread_id": f"scan_{current_target}"}}
            workflow = build_workflow(
                checkpointer=st.session_state.workflow_memory,
                interrupt_before=["attack_path"]
            )
            
            # 1. Execute workflow up to the interrupt (Enrichment -> Recommendation)
            with st.spinner("Research Agent integrating Threat Intelligence and generating Recommendations..."):
                initial_state = GraphState(
                    target_identifier=current_target,
                    scan_findings=findings_for_workflow,
                    executed_tools=[], 
                    recommended_tools=[],
                    enriched_rag_data=[],
                    attack_path_graph=None,
                    error=None
                )
                
                # invoke will run until the interrupt before "attack_path"
                final_state = workflow.invoke(initial_state, config=thread_config)
                
            if final_state.get("error"):
                st.error(f"Workflow encountered an error: {final_state['error']}")
            else:
                # A. Enriched Context (Research Agent)
                if final_state.get("enriched_rag_data"):
                    st.subheader("📚 Enriched Threat Intelligence")
                    with st.expander("View RAG Context Data", expanded=True):
                        st.json(final_state["enriched_rag_data"])

                # B. Dynamic Recommendations (Planning Agent mapping)
                if final_state.get("recommended_tools"):
                    st.subheader("💡 Dynamic Scan Suggestions")
                    for idx, rec in enumerate(final_state["recommended_tools"], 1):
                        st.info(f"**Suggested Step {idx}:** Run `{rec.get('tool')}`\n\n`{rec.get('command')}`")

                st.markdown("---")
                st.header("🕸️ Phase 2: Attack Path Generation")
                st.write("The Research Agent has processed the vulnerabilities and the Planning Agent has recommended the next dynamic scans. You can now engage the Attack Path Agent to visualize the structural attack vectors.")
                
                # Manual trigger for Attack Path
                if st.button("🚀 Call Attack Path Generator Agent", type="primary"):
                    st.session_state.attack_path_generated = True
                    
                if st.session_state.get("attack_path_generated"):
                    with st.spinner("Attack Path Agent is querying Chroma & Neo4j to generate the Graphviz map..."):
                        # Resume the graph from the breakpoint
                        resumed_state = workflow.invoke(None, config=thread_config)
                        
                    if resumed_state.get("attack_path_graph"):
                        st.subheader("🕸️ Attack Path Visualization")
                        try:
                            st.graphviz_chart(resumed_state["attack_path_graph"])
                        except Exception as e:
                            st.warning("Could not render graph interactively. Raw DOT syntax below:")
                            st.code(resumed_state["attack_path_graph"], language="dot")

if __name__ == "__main__":
    main()


