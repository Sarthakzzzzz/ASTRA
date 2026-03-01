import json
from .llm_client import get_model
from ..scanner_registry import TOOL_BINARIES
from ..rule_interpreter import get_rules_context_for_ai, match_rules_to_findings, format_matched_rules_for_ai
from .exploit_search import search_exploitdb, format_exploits_for_ai

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

def get_tool_list():
    """Returns available tool names from TOOL_BINARIES."""
    return list(TOOL_BINARIES.keys())

# Default command templates for tools (used as fallback if AI doesn't generate proper commands)
DEFAULT_COMMANDS = {
    'nuclei': 'nuclei -target {target} -templates cves,misconfigurations,vulnerabilities -severity critical,high',
    'nikto': 'nikto -h {target} -maxtime 3',
    'wpscan': 'wpscan --url {target} --enumerate u,p,at',
    'sqlmap': 'sqlmap -u "{target}" --batch --risk=2 --level=2',
    'dirb': 'dirb {target} /usr/share/wordlists/dirb/common.txt -r',
    'ffuf': 'ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403,405',
    'enum4linux': 'enum4linux -a {target}',
    'sslyze': 'sslyze --json_out output.json {target}',
    'joomscan': 'joomscan --url {target}',
    'vulners': 'nmap --script vuln,default -sV {target}',
    'nmap-ssh-scripts': 'nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -sV {target}',
    'nmap-ftp-scripts': 'nmap -p 21 --script ftp-anon,ftp-vsftpd-backdoor -sV {target}',
    'nmap-smb-scripts': 'nmap -p 139,445 --script smb-os-discovery,smb-vuln-ms17-010 -sV {target}',
    'whatweb': 'whatweb {target}',
}

def generate_default_command(tool_name, target):
    """Generate a default command for a tool if AI doesn't provide one."""
    cmd_template = DEFAULT_COMMANDS.get(tool_name, f'{tool_name} {target}')
    return cmd_template.replace('{target}', target)

def analyze_dynamic_scan(findings, executed_tools, summary_mode=False):
    """
    Analyzes enriched findings (with capability and risk_level) using LangChain.
    Returns a list of recommended next tools to run based on findings or summary if summary_mode=True.
    """
    try:
        model = get_model(json_mode=True)
    except Exception as e:
        print(f"[AI] Warning: Could not initialize LangChain model: {e}")
        return [] if not summary_mode else None
    
    # Create enriched summary that includes capability and risk_level
    summary = []
    for f in findings:
        summary.append({
            "type": f.finding_type,
            "value": f.finding_value,
            "target": f.target,
            "capability": getattr(f, 'capability', None),
            "risk_level": getattr(f, 'risk_level', 'info'),
            "severity": getattr(f, 'severity', None),
            "description": getattr(f, 'description', '')
        })
    
    available_tools = get_tool_list()
    
    # Get rules context for better AI decision-making
    try:
        rules_context = get_rules_context_for_ai()
        matched_rules = match_rules_to_findings(findings)
        matched_rules_text = format_matched_rules_for_ai(matched_rules)
    except Exception as e:
        print(f"[!] Warning: Could not load rules context: {e}")
        rules_context = ""
        matched_rules_text = ""
    
    # Search ExploitDB for relevant exploits
    exploitdb_context = ""
    try:
        for f in findings:
            service = getattr(f, 'service', '')
            version = getattr(f, 'version', '')
            if service and version:
                exploits = search_exploitdb(software=service, version=version)
                if exploits:
                    exploitdb_context += format_exploits_for_ai(exploits)
                    break
    except Exception as e:
        print(f"[!] Warning: ExploitDB search failed: {e}")

    if summary_mode:
        prompt_template = ChatPromptTemplate.from_template("""
        You are a cybersecurity expert. Analyze these scan findings and provide a comprehensive security assessment.

        FINDINGS FROM SECURITY SCAN:
        {findings_json}

        {exploitdb_context}

        PROVIDE A COMPREHENSIVE SECURITY ANALYSIS INCLUDING:
        1. Executive Summary of security posture
        2. Critical vulnerabilities found with CVE IDs if available
        3. Risk assessment and impact analysis
        4. Recommended remediation steps
        5. Attack vectors and potential exploitation paths

        RESPONSE: Return this JSON structure only:
        {{"summary": "comprehensive security analysis text with CVE IDs, vulnerabilities, and recommendations"}}

        Generate detailed security analysis:
        """)
        
        chain = prompt_template | model | JsonOutputParser()
        
        try:
            result = chain.invoke({
                "findings_json": json.dumps(summary, indent=2),
                "exploitdb_context": exploitdb_context
            })
            return result
        except Exception as e:
            print(f"[AI] Summary generation failed: {e}")
            return None
    
    # Original tool recommendation logic
    prompt_template = ChatPromptTemplate.from_template("""
    You are a security orchestration AI. Analyze ALL findings cumulatively and generate specific security tool commands for next scans.

    CUMULATIVE FINDINGS FROM ALL SCANS SO FAR:
    {findings_json}

    {matched_rules_text}

    {exploitdb_context}

    {rules_context}

    TOOLS ALREADY EXECUTED: {executed_tools}
    AVAILABLE TOOLS FOR NEXT SCANS: {available_tools}

    ANALYSIS INSTRUCTIONS:
    1. Review ALL findings comprehensively - they represent cumulative scan results
    2. Use MATCHED RULES to identify high-priority tool recommendations
    3. Identify gaps and unexplored areas based on current findings
    4. Find services/versions that need deeper scanning
    5. Prioritize exploit-level findings first
    6. Use DECISION RULES to match findings with appropriate tools
    7. Recommend tools that will expand on discovered capabilities

    COMMAND EXAMPLES:
    - nuclei -target http://45.33.32.156 -templates cves,misconfigurations,vulnerabilities -severity critical,high
    - nmap --script vulners -p 22 45.33.32.156
    - nikto -h http://45.33.32.156 -maxtime 3
    - wpscan --url http://45.33.32.156 --enumerate u,p,at
    - sqlmap -u "http://45.33.32.156/page?id=1" --batch --risk=2 --level=2
    - dirb http://45.33.32.156 /usr/share/wordlists/dirb/common.txt
    - ffuf -u http://45.33.32.156/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403,405
    - enum4linux -a 45.33.32.156
    - sslyze --json_out output.json 45.33.32.156
    - joomscan --url http://45.33.32.156
    - nmap-ssh-scripts: nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos 45.33.32.156
    - nmap-ftp-scripts: nmap -p 21 --script ftp-anon,ftp-vsftpd-backdoor 45.33.32.156
    - nmap-smb-scripts: nmap -p 139,445 --script smb-os-discovery,smb-vuln-ms17-010 45.33.32.156

    RULES:
    1. Only recommend from AVAILABLE TOOLS
    2. Never recommend tools already in TOOLS ALREADY EXECUTED
    3. Relate all findings - what they tell us collectively
    4. Find services that need deeper investigation
    5. Include complete flags and target addresses
    6. Return ONLY valid JSON - no markdown
    7. NEVER use '--script all' with nmap — it runs 600+ scripts and takes hours. Use specific script categories like '--script vuln,default' or named scripts only.
    8. For nmap scripts, always scope to specific ports with -p flag
    9. nikto commands MUST include '-maxtime 3' flag to limit scan time to 3 minutes

    RESPONSE: Return this JSON structure only:
    {{"reasoning": "how findings relate and what gaps exist", "recommendations": [{{"tool": "nuclei", "command": "nuclei -target http://TARGET -templates cves", "rationale": "why this will help"}}, {{"tool": "vulners", "command": "nmap --script vulners TARGET", "rationale": "why this will help"}}]}}

    Generate next scan recommendations based on cumulative findings:
    """)
    
    chain = prompt_template | model | JsonOutputParser()
    
    try:
        print(f"[AI] Analyzing {len(findings)} cumulative findings using LangChain...")
        
        result = chain.invoke({
            "findings_json": json.dumps(summary, indent=2),
            "matched_rules_text": matched_rules_text,
            "exploitdb_context": exploitdb_context,
            "rules_context": rules_context,
            "executed_tools": executed_tools,
            "available_tools": available_tools
        })
        
        reasoning = result.get("reasoning", "")
        recommendations = result.get("recommendations", [])
        
        if not isinstance(recommendations, list):
            recommendations = [recommendations] if recommendations else []
        
        # Ensure all recommendations have proper commands
        for rec in recommendations:
            tool_name = rec.get("tool", "")
            if not rec.get("command") or len(rec.get("command", "").strip()) < 5:
                target = ""
                for f in findings:
                    if f.target:
                        target = f.target
                        break
                if target:
                    rec["command"] = generate_default_command(tool_name, target)
        
        return recommendations

    except Exception as e:
        print(f"[AI] Failed to get AI recommendations: {e}")
        return []