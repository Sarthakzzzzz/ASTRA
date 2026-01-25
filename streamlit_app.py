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
    from orchestrator.core import engine, utils, dependencies
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
OUTPUT_DIR = Path("output/raw")

# --- UI Helper Functions ---

def display_scan_results(primary_target: str):
    """
    Finds and displays formatted results from output files in expanders.
    """
    st.markdown("---")
    st.header("📊 Scan Results")

    sanitized_target = utils.sanitize_target(primary_target)

    try:
        # A more robust way to find all files related to this specific scan target
        result_files = sorted([
            f for f in OUTPUT_DIR.iterdir()
            if sanitized_target in f.name
        ])
    except FileNotFoundError:
        st.warning("Output directory not found. A scan must be run to generate results.")
        return

    if not result_files:
        st.info("No result files found for this target. The scan may have failed or produced no output.")
        return

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
                    else:
                        st.text("File is empty.")
                except Exception as e:
                    st.error(f"Could not read or display file: {e}")


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
                default=["nmap", "whatweb", "nikto"],
                help="Choose the specific tools you want to run in Static mode."
            )
        else: # Dynamic mode
            st.info("🤖 **Dynamic Mode:** AI-powered adaptive scanning with ExploitDB integration")
            st.markdown("- Automatically searches ExploitDB for discovered services")
            st.markdown("- Intelligently chains tools based on findings")
            st.markdown("- Uses rules engine for targeted exploitation")
            # In dynamic mode, we provide a base set of tools to start the chain reaction.
            enabled_scanners = ["nmap", "whatweb", "nuclei", "nikto"]

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
                # --- UPDATED: Call the orchestrator engine with the selected mode ---
                scan_generator = engine.run_orchestrator(
                    primary_target=target,
                    mode=scan_mode, # Pass the selected mode
                    enable_arg=",".join(enabled_scanners),
                    concurrency=concurrency,
                    dry_run=False
                )

            # Iterate through the generator to get live log lines
            for line in scan_generator:
                log_content += line
                log_container.code(log_content, language="log")

            st.success("✅ Scan completed!")

            # Display results automatically after the scan
            display_scan_results(target)

        except Exception as e:
            st.error(f"A critical error occurred during the scan: {e}")
            log_container.code(log_content, language="log") # Show logs up to the point of failure

if __name__ == "__main__":
    main()


