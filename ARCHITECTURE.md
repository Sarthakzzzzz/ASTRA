# ASTRA Cumulative Analysis - Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ASTRA SECURITY ORCHESTRATOR                         │
│              AI-Driven Cumulative Multi-Round Scanning                 │
└─────────────────────────────────────────────────────────────────────────┘

                              Target: 45.33.32.156
                                      │
                ┌───────────────────────┴───────────────────────┐
                │                                               │
         ┌──────▼──────┐                                        │
         │ orchestrator/  │                                     │
         │ main.py      │                                       │
         └──────┬──────┘                                        │
                │                                               │
         ┌──────▼──────────────────────┐                        │
         │ engine.py                   │                        │
         │ - Manages iterations        │                        │
         │ - Tracks master_findings    │                        │
         │ - Coordinates scanners      │                        │
         └──────┬──────────────────────┘                        │
                │                                               │
    ┌───────────┴────────────┬────────────┬───────────┐        │
    │                        │            │           │        │
    ▼                        ▼            ▼           ▼        ▼
┌────────┐  ┌──────────┐  ┌────────┐  ┌──────┐    master_
│  nmap  │  │ whatweb  │  │ nuclei │  │ nikto│    findings
│ (recon)│  │ (tech)   │  │ (vuln) │  │(web)│    list
└───┬────┘  └──────┬───┘  └───┬────┘  └──┬───┘    (cumulative)
    │              │          │         │
    └──────────────┼──────────┼─────────┘
                   │          │
            ┌──────▼──────────▼──────┐
            │  Parse Outputs        │
            │  - parse_nmap_xml     │
            │  - parse_whatweb_json │
            │  - parse_nuclei_jsonl │
            │  - parse_nikto_txt    │  ◄──── NEW
            └──────┬────────────────┘
                   │
         ┌─────────▼─────────┐
         │ StandardFinding   │
         │ - capability      │
         │ - risk_level      │
         │ - severity        │
         │ - details         │
         └─────────┬─────────┘
                   │
              ALL findings accumulated in master_findings_list
                   │
    ┌──────────────▼──────────────┐
    │   planning_agent.py         │
    │   AI Analysis Engine        │
    │  (Gemini 2.5 Flash)        │
    │                            │
    │ Input: 40-200+ findings    │
    │ Process: Analyze ALL       │
    │          findings          │
    │          together          │
    │ Output: Recommendations    │
    │         with commands      │
    └──────────────┬─────────────┘
                   │
    ┌──────────────▼──────────────┐
    │ Recommendations             │
    │ {                           │
    │   "reasoning": "how...",    │
    │   "recommendations": [      │
    │     {                       │
    │       "tool": "wpscan",     │
    │       "command": "...",     │
    │       "rationale": "..."    │
    │     }                       │
    │   ]                         │
    │ }                           │
    └──────────────┬─────────────┘
                   │
         ┌─────────▼──────────┐
         │  runner.py         │
         │  Execute Commands  │
         └─────────┬──────────┘
                   │
              New Findings Collected
                   │
         ┌─────────▼──────────┐
         │ Add to             │
         │ master_findings    │
         │ (100+ total now)   │
         └─────────┬──────────┘
                   │
      Iteration 2 → AI sees complete picture + new findings
      Iteration 3 → Even better recommendations
```

## Data Flow - Iteration by Iteration

```
┌────────────────────────────────────────────────────────────────┐
│                      ITERATION 1                               │
└────────────────────────────────────────────────────────────────┘

nmap scanme.nmap.156
  ├─ Port 22: ssh (OpenSSH 6.6.1)
  ├─ Port 80: http (Apache 2.4.41)
  └─ Port 9929: tcpwrapped

[PARALLEL]

whatweb http://scanme.nmap.org:80
  ├─ Apache 2.4.41
  ├─ PHP 7.4.3
  └─ jQuery 3.4.1

nuclei -target http://scanme.nmap.org:80
  ├─ CVE-2021-41733 (Apache Auth Bypass)
  ├─ Exposed .git directory
  └─ Weak SSL cipher

nikto -h http://scanme.nmap.org:80
  ├─ Directory indexing enabled (/)
  ├─ Missing cookie security flags
  ├─ Server version disclosed
  └─ CGI directory accessible

                            ▼

                  47 FINDINGS TOTAL
        [nmap:5 + whatweb:3 + nuclei:4 + nikto:8]

                            ▼

              AI ANALYZES 47 FINDINGS TOGETHER
         (Not individually, but holistically)

              "Apache 2.4.41 with known CVEs +
               directory indexing + weak crypto +
               PHP RFI risk = CRITICAL"

                            ▼

        AI RECOMMENDS: wpscan, nmap-ssh, dirb
                            │
┌────────────────────────────────────────────────────────────────┐
│                      ITERATION 2                               │
└────────────────────────────────────────────────────────────────┘

wpscan --url http://scanme.nmap.org
  ├─ WordPress 5.8 found
  └─ 8 vulnerable plugins (RFI, XSS)

nmap -p 22 --script ssh-auth-methods scanme.nmap.org
  ├─ Password authentication enabled
  ├─ Key-based authentication available
  └─ Algorithm: diffie-hellman-group14-sha256

dirb http://scanme.nmap.org
  ├─ /admin/ found
  ├─ /backup/ found
  ├─ /config/ found (403)
  └─ /uploads/ found (rwx)

                            ▼

                  77 FINDINGS TOTAL
    [previous 47 + new findings from 3 tools]

                            ▼

        AI ANALYZES 77 FINDINGS TOGETHER
    (Previous context + new discoveries = better analysis)

        "WordPress vulnerability + weak SSH +
         exposed directories = RCE POSSIBLE"

                            ▼

        AI RECOMMENDS: sqlmap, enum4linux
                            │
┌────────────────────────────────────────────────────────────────┐
│                      ITERATION 3                               │
└────────────────────────────────────────────────────────────────┘

sqlmap -u "http://scanme.nmap.org/index.php?id=1"
  ├─ SQL injection found in 'id' parameter
  ├─ Database: MySQL 5.7.32
  └─ Current user: wordpress_user

enum4linux -a scanme.nmap.org
  ├─ NETBIOS Name: SCANME
  ├─ Shares available (guest access)
  └─ Users: admin, test

                            ▼

                  100 FINDINGS TOTAL
    [previous 77 + new findings = comprehensive picture]

                            ▼

         AI FINAL ANALYSIS: 100 FINDINGS
        "Complete vulnerability map created.
         Multiple exploitation paths identified."

                            ▼

                    SCAN COMPLETE
```

## Master Findings List Growth

```
Iteration 1          Iteration 2          Iteration 3
┌──────────┐         ┌──────────┐        ┌──────────┐
│ nmap: 5  │         │ prev: 47 │        │ prev: 77 │
│ whatweb:3│  +      │ wpscan:8 │  +     │ sqlmap:5 │  +
│ nuclei: 4│         │ nmap-ssh:4│       │ enum4linux:5│
│ nikto: 8 │         │ dirb: 8  │        │          │
└──────────┘         └──────────┘        └──────────┘
   47 total           77 total           100+ total
   findings           findings            findings

    ↓                   ↓                   ↓
   AI sees            AI sees             AI sees
  4 tools'         ALL 4 tools +       ALL previous
  findings         3 new tools'        + 2 new tools'
   only           findings together     findings together
```

## Parser Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     PARSER MAPPING                         │
└────────────────────────────────────────────────────────────┘

Tool Output              Parser Function         Enriched Finding
   │                            │                       │
   ├─ nmap output.xml   →  parse_nmap_xml        StandardFinding
   │  (XML format)          • Extract ports      • capability ✓
   │                        • Extract services  • risk_level ✓
   │                        • Extract versions  • severity ✓
   │                                            • details ✓
   │
   ├─ whatweb.json      →  parse_whatweb_json   StandardFinding
   │  (JSON array)          • Parse tech stack  • capability ✓
   │                        • Extract versions  • risk_level ✓
   │                        • Map to risks      • severity ✓
   │                                            • details ✓
   │
   ├─ nuclei.jsonl      →  parse_nuclei_jsonl   StandardFinding
   │  (JSONL format)        • Extract CVEs      • capability ✓
   │                        • Map severities    • risk_level ✓
   │                        • Extract templates • severity ✓
   │                                            • details ✓
   │
   └─ nikto.txt         →  parse_nikto_txt      StandardFinding ◄── NEW
      (Text format)        • Extract OSVDB IDs  • capability ✓
                           • Parse severity     • risk_level ✓
                           • Map to configs     • severity ✓
                                                • details ✓

          All → Accumulated in master_findings_list → Passed to AI
```

## AI Analysis Process

```
┌──────────────────────────────────────────────────────────────┐
│              AI CUMULATIVE ANALYSIS PROCESS                 │
│                  (planning_agent.py)                        │
└──────────────────────────────────────────────────────────────┘

Input: All 47 (or 77, or 100+) findings
       ├─ From nmap: ports, services, versions
       ├─ From whatweb: technologies, frameworks
       ├─ From nuclei: known CVEs, exploits
       └─ From nikto: misconfigurations, headers

        ▼

   AI Receives Prompt:
   "Analyze ALL findings cumulatively.
    Consider how they relate to each other.
    What do they tell us collectively?"

        ▼

   AI Processes:
   ├─ Extracts key capabilities
   ├─ Identifies attack paths
   ├─ Prioritizes high-risk findings
   ├─ Identifies gaps to investigate
   └─ Correlates across tools

        ▼

   AI Reasons:
   "Found Apache + PHP + WordPress + known CVEs +
    directory indexing + weak SSL. Recommend:
    - WordPress-specific scanning (wpscan)
    - SSH enumeration (SSH brute-force)
    - Directory discovery (dirb)"

        ▼

   Output: JSON Recommendations
   {
     "reasoning": "Complete analysis string",
     "recommendations": [
       {
         "tool": "tool_name",
         "command": "complete command string",
         "rationale": "why this helps"
       }
     ]
   }

        ▼

   Execute Recommended Tools
   Collect New Findings
   Add to master_findings_list
   Next Iteration Gets Complete History
```

## Execution Timeline

```
Time →

T0:00  [*] Start ASTRA with target
       ├─ Load configuration
       ├─ Initialize engine
       └─ Parse command-line arguments

T0:10  [~] Running initial group: nmap
       ├─ Execute: nmap -sS -sV -T4 ...
       └─ Collect: 5 findings

T0:30  [~] Running initial group: whatweb, nuclei, nikto (PARALLEL)
       ├─ Execute: whatweb ...
       ├─ Execute: nuclei ...
       ├─ Execute: nikto ...
       └─ Collect: 15 findings (total 20)

T1:00  [*] Initial group completed, collected 47 findings total

       [AI] Analyzing 47 cumulative findings...
       [AI] Strategy: Apache + PHP + WordPress detected...
       [AI] Recommending: wpscan, nmap-ssh, dirb

T1:10  [~] Running iteration 2 group: wpscan, nmap-ssh, dirb (PARALLEL)
       ├─ Execute recommended tools
       └─ Collect: 30 new findings (total 77)

T1:50  [*] Iteration 2 completed, collected 77 findings total

       [AI] Analyzing 77 cumulative findings...
       [AI] Strategy: WordPress vulns + weak SSH + exposed dirs...
       [AI] Recommending: sqlmap, enum4linux

T2:00  [~] Running iteration 3 group: sqlmap, enum4linux (PARALLEL)
       ├─ Execute recommended tools
       └─ Collect: 23 new findings (total 100)

T2:45  [*] Iteration 3 completed, collected 100+ findings total

       [AI] Final comprehensive analysis...
       [✓] Scanning complete. Generated full vulnerability map.

T2:50  [Summary] Total findings: 102
       ├─ Critical: 8
       ├─ High: 15
       ├─ Medium: 24
       └─ Low: 55
```

## Key Improvements Over Previous Architecture

```
BEFORE                          AFTER
─────────────────────────────── ──────────────────────────────
Single tool focus               4 parallel initial tools
Individual findings             Cumulative findings
Limited correlation             Cross-tool analysis
Fragmented understanding        Holistic picture
Static recommendations          AI-driven iterations
Few findings per scan           100+ findings per scan
No iteration context            Each iteration sees all history
Limited depth                   Progressive deeper investigation
```

---

This architecture enables ASTRA to perform truly intelligent security scanning where each iteration builds on the comprehensive knowledge from previous rounds, resulting in more effective vulnerability discovery and more targeted tool recommendations.
