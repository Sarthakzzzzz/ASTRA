
import logging
import asyncio
import os
from typing import List, Dict, Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
if not OPENROUTER_API_KEY:
    print("[!] Warning: OPENROUTER_API_KEY not found in environment. Agent may fail.")

# Pass key to LiteLLM via its OpenAI-compatible env var
os.environ["OPENAI_API_KEY"] = OPENROUTER_API_KEY

try:
    from google.adk.agents import Agent
    from google.adk.sessions import InMemorySessionService
    from google.adk.runners import Runner
    from google.adk.models.lite_llm import LiteLlm
    import google.genai.types as types
except ImportError:
    # Fallback for development/testing if package missing
    print("[!] Warning: google-adk not found. Using mock classes.")
    
    class Agent:
        def __init__(self, name, model, description, instruction, tools): pass

    class InMemorySessionService:
        async def create_session(self, app_name, user_id, session_id): return "mock_session"

    class Runner:
        def __init__(self, agent, app_name, session_service): self.agent = agent
        async def run_async(self, user_id, session_id, new_message):
             yield MockEvent("Mock analysis complete.")

    class MockEvent:
        def __init__(self, text): self.text = text
        def is_final_response(self): return True
        @property
        def content(self): return type('obj', (object,), {'parts': [type('obj', (object,), {'text': self.text})]})()
    
    class types:
        class Content:
             def __init__(self, role, parts): pass
        class Part:
             def __init__(self, text): pass

from google_adk.client import get_openrouter_model
from google_adk.tools import ScanTools
from orchestrator.core.registry import TOOL_BINARIES
from orchestrator.core.rules_loader import get_rules_context_for_ai, match_rules_to_findings, format_matched_rules_for_ai
from google_adk.exploitdb import search_exploitdb, format_exploits_for_ai
from orchestrator.core import state

logger = logging.getLogger(__name__)

# Wrap tools for the agent
# Note: Tools must be standalone functions for ADK to introspect them correctly
def get_cve_details(cve_id: str) -> str:
    """
    Fetches detailed information for a CVE from NVD, including severity and potential exploits.
    Args:
        cve_id: The CVE ID to search for (e.g., CVE-2023-1234).
    """
    return ScanTools.get_cve_details(cve_id)

def recommend_tool(service: str, port: int) -> str:
    """
    Suggests a specific tool command to run for a given service and port.
    Args:
        service: The service name (e.g., 'ssh', 'http').
        port: The port number.
    """
    return ScanTools.recommend_tool_command(service, port)

def suggest_scan(target: str, scan_type: str, reason: str) -> str:
    """
    Suggests a follow-up scan for a target.
    Args:
        target: The target IP or URL.
        scan_type: The type of scan (e.g., 'Nikto', 'Nmap Vulners').
        reason: Why this scan is needed.
    """
    return ScanTools.suggest_scan(target, scan_type, reason)

def add_attack_node(type: str, value: str, parent_id: str) -> str:
    """
    Adds a node to the attack graph.
    Args:
        type: Node type ('technique', 'impact', 'vulnerability').
        value: Name/Description of the node (e.g., 'Remote Code Execution').
        parent_id: ID of the parent node or Finding ID this connects to.
    """
    return ScanTools.add_attack_node(type, value, parent_id)

class ScanAgent:
    """
    Wrapper around Google ADK Agent to provide synchronous interface for the Orchestrator.
    """
    def __init__(self, model_name: str = None):
        model_name = model_name or get_openrouter_model()
        self.model_name = model_name
        self.app_name = "astra_security_scan"
        self.user_id = "astra_user"
        self.session_id = "current_scan_session"

        litellm_model = LiteLlm(
            model=f"openai/{model_name}" if "/" not in model_name else model_name,
            api_base="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
        )

        # Initialize ADK components
        self.adk_agent = Agent(
            name="security_consultant",
            model=litellm_model,
            description="Expert security consultant and penetration tester.",
            instruction=(
                "You are an expert penetration tester assisting with a security scan. "
                "Analyze the provided findings. Identify critical vulnerabilities (CVEs). "
                "Analyze the provided findings. Identify critical vulnerabilities (CVEs). "
                "Use the 'get_cve_details' tool to verify CVE severity and check for exploit references. "
                "Use 'add_attack_node' to build an attack graph linking findings to techniques and impacts. "
                "Use 'suggest_scan' to request further info if needed. "
                "Provide a concise, actionable summary of the most dangerous findings and what to do next."
            ),
            tools=[get_cve_details, recommend_tool, suggest_scan, add_attack_node]
        )
        
        self.session_service = InMemorySessionService()
        self.runner = Runner(
            agent=self.adk_agent,
            app_name=self.app_name,
            session_service=self.session_service
        )
        self._sync_runner = asyncio.Runner()
        self.latest_reasoning = "Waiting for scan data..."

    def _run_sync(self, coroutine):
        return self._sync_runner.run(coroutine)

    async def _run_analysis_async(self, prompt: str) -> str:
        # Ensure session exists
        try:
            await self.session_service.create_session(
                app_name=self.app_name,
                user_id=self.user_id,
                
                session_id=self.session_id
            )
        except Exception as e:
            # Session likely already exists, which is fine
            logger.debug(f"Session creation skipped (may already exist): {e}")
        
        content = types.Content(role='user', parts=[types.Part(text=prompt)])
        
        final_response_text = "No response generated."
        
        # Run agent asynchronously
        async for event in self.runner.run_async(
            user_id=self.user_id,
            session_id=self.session_id,
            new_message=content
        ):
            if hasattr(event, 'is_final_response') and event.is_final_response():
                if event.content and event.content.parts:
                    final_response_text = event.content.parts[0].text
            # Handle mock event which might not have is_final_response method if not mocked correctly
            # But our mock has it.
                
        return final_response_text

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> str:
        """
        Main entry point for the agent to analyze a list of findings.
        Synchronous wrapper.
        """
        # specialized prompt construction
        finding_summaries = []
        for f in findings:
            cve = "N/A"
            val = "N/A"
            typ = "unknown"

            if hasattr(f, "cve_id"):
                cve = getattr(f, "cve_id", "N/A") or "N/A"
                val = getattr(f, "finding_value", "N/A")
                typ = getattr(f, "finding_type", "unknown")
            elif isinstance(f, dict):
                cve = f.get("cve_id", "N/A")
                val = f.get("finding_value", "N/A")
                typ = f.get("finding_type", "unknown")
            
            finding_summaries.append(f"- Type: {typ}, Value: {val}, CVE: {cve}")

        prompt = (
            "Here are the latest scan findings:\n"
            + "\n".join(finding_summaries) + "\n\n"
            "Analyze these findings. Prioritize any CVEs with high scores or known exploits. "
            "Suggest the next best actions."
        )
        
        try:
            return self._run_sync(self._run_analysis_async(prompt))
        except Exception as e:
            logger.error(f"Agent execution failed: {e}")
            return f"Agent error: {e}"

    def recommend_next_scans(self, findings: List[Dict[str, Any]], executed_tools: List[str]) -> List[Dict[str, str]]:
        """
        Recommends next scan tools based on findings, rules, and exploitdb data.
        Returns list of recommendations: [{"tool": "tool_name", "target": "target", "reason": "why"}]
        """
        # 1. Enrich findings summary
        finding_summaries = []
        services_detected = []
        
        for f in findings:
            if isinstance(f, dict):
                typ = f.get("finding_type", "unknown")
                val = f.get("finding_value", "N/A")
                risk = f.get("risk_level", "unknown")
                version = f.get("version", "")
            else:
                # Assume object
                typ = getattr(f, "finding_type", "unknown")
                val = getattr(f, "finding_value", "N/A")
                risk = getattr(f, "risk_level", "unknown")
                version = getattr(f, "version", "")
            
            finding_summaries.append(f"- {typ}: {val} (risk: {risk})")
            
            # Track services for ExploitDB search
            if typ == "service" or typ == "open_port":
                 services_detected.append((val, version))

        # 2. Get Rules Context
        try:
            rules_context = get_rules_context_for_ai()
            matched_rules = match_rules_to_findings(findings)
            matched_rules_text = format_matched_rules_for_ai(matched_rules)
            if matched_rules_text:
                rules_context += "\nMATCHED RULES:\n" + matched_rules_text
        except Exception as e:
            logger.warning(f"Could not load rules context: {e}")
            rules_context = "No specific rules matched."

        # 3. Search ExploitDB
        exploitdb_context = ""
        try:
            for service, version in services_detected:
                if service and version:
                    exploits = search_exploitdb(software=service, version=version)
                    if exploits:
                        exploitdb_context += format_exploits_for_ai(exploits) + "\n"
        except Exception as e:
            logger.warning(f"ExploitDB search error: {e}")

        # 4. Construct Comprehensive Prompt
        available_tools = list(TOOL_BINARIES.keys())
        
        prompt = (
            f"You are the Planning Agent for a cybersecurity scanner. \n"
            f"Based on these findings:\n" + "\n".join(finding_summaries[:30]) + "\n\n"
            
            f"CONTEXT - EXPLOITDB SEARCH RESULTS:\n{exploitdb_context}\n\n"
            f"CONTEXT - ENGAGEMENT RULES:\n{rules_context}\n\n"
            
            f"Already executed tools: {', '.join(executed_tools)}\n"
            f"Available tools: {', '.join(available_tools)}\n\n"
            
            "Recommend 2-3 specific tools to run next that haven't been executed yet. "
            "Consider the findings, potential exploits, and rules. "
            "Provide a 'reasoning' summary of the situation, and then the list of tool recommendations. "
            "Format as JSON object: { \"reasoning\": \"Detailed analysis of the situation...\", \"recommendations\": [{\"tool\": \"name\", \"target\": \"target\", \"reason\": \"why\"}] }"
        )
        
        try:
            logger.info("Requesting AI recommendations from Google ADK...")
            response = self._run_sync(self._run_analysis_async(prompt))
            
            # Try to parse JSON from response
            import json
            import re
            
            # Extract JSON object from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                
                # Store reasoning
                self.latest_reasoning = data.get("reasoning", "Analysis unavailable.")
                state.update_reasoning(self.latest_reasoning)
                
                # Return recommendations
                recommendations = data.get("recommendations", [])
                # Filter out already executed tools
                return [r for r in recommendations if r.get("tool") not in executed_tools]
            else:
                logger.warning(f"Could not parse recommendations from: {response}")
                return []
        except Exception as e:
            logger.error(f"Failed to get recommendations: {e}")
            return []

        self.latest_reasoning = "Waiting for scan data..."

    def get_latest_reasoning(self) -> str:
        return self.latest_reasoning

    async def answer_question_async(self, context: str, question: str) -> str:
        """
        Async version of answer_question.
        """
        prompt = (
            f"Context (Logs/Data):\n{context}\n\n"
            f"User Question: {question}\n\n"
            "Please provide a helpful, concise answer as a security expert."
        )
        try:
            return await self._run_analysis_async(prompt)
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return f"I encountered an error processing your request: {e}"

    def answer_question(self, context: str, question: str) -> str:
        """
        Answers a user question based on provided context (e.g., logs).
        Synchronous wrapper.
        """
        try:
            return self._run_sync(self.answer_question_async(context, question))
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return f"Agent error: {e}"
