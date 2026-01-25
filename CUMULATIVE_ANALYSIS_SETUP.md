# ASTRA System - Cumulative Analysis Setup Complete ✓

## Overview
ASTRA has been successfully configured for **cumulative, AI-driven security scanning** with intelligent multi-round discovery. The system now:

1. **Runs Initial Scanners in Parallel**: Nmap (dependency) → WhatWeb + Nuclei + Nikto (parallel)
2. **Analyzes ALL Findings Cumulatively**: AI reviews complete findings from all tools together
3. **Generates Intelligent Recommendations**: Based on holistic understanding of vulnerabilities
4. **Iterates Intelligently**: Each round builds on previous findings (up to 3 iterations)

## System Architecture

### Initial Scanner Group
```
nmap (reconnaissance)
  ├─ whatweb (technology fingerprinting)
  ├─ nuclei (vulnerability scanning)
  └─ nikto (web hardening checks)
```

**Parallel Execution**: WhatWeb, Nuclei, and Nikto run simultaneously after Nmap completes.

### Cumulative Analysis Flow
```
Iteration 1: nmap → [whatweb + nuclei + nikto] → AI analyzes 4 tools' findings
    ↓
Iteration 2: AI recommends next tools based on findings → Execute → Analyze ALL findings
    ↓
Iteration 3: AI recommends more tools based on expanded knowledge → Execute → Final analysis
```

## Configuration Status

### ✅ Registry Configuration (`orchestrator/core/registry.py`)
- **Nikto Enabled**: `"enabled": True`
- **Nikto Placement**: Initial group (depends_on: ["nmap"])
- **Command Template**: `nikto -h {scan_target} -o orchestrator/output/raw/{file_target}_nikto.txt`
- **Requires URL**: Yes (requires_url: True)

### ✅ Default Scanners (`orchestrator/main.py`)
- **Default Value**: `"nmap,whatweb,nuclei,nikto"`
- **Users get Nikto automatically** without specifying --enable flag

### ✅ Parser Integration (`orchestrator/core/parsers.py`)
- **Nikto Parser Added**: `parse_nikto_txt()` function
- **Parser Mapping**: Nikto registered in `PARSER_MAPPING`
- **Enrichment Fields**: All nikto findings include:
  - `capability`: Web vulnerability classification
  - `risk_level`: Assessment (enum, misconfig, exploit)
  - `severity`: Finding level
  - `details`: Full OSVDB context

### ✅ AI Cumulative Analysis (`orchestrator/core/ai/planning_agent.py`)
- **Enhanced Prompt**: Explicitly instructs AI to analyze ALL cumulative findings
- **Logging Output**: Shows `"Analyzing X cumulative findings from all scans..."`
- **Context**: Passes complete finding history each iteration
- **Reasoning**: AI explains how findings relate holistically

### ✅ Engine Architecture (`orchestrator/core/engine.py`)
- **Master Findings List**: Accumulates findings across all iterations
- **Cumulative Passing**: Engine passes all findings to AI each iteration
- **Status Display**: Shows `"Iteration X: Collected Y findings"`

## Testing Results

### Parser Validation ✓
```
[+] Nikto in enabled scanners: True
[+] Nikto parser registered: True
[+] Found 1 findings from Nikto parser
    - Nikto: web_config (capability: web_config, risk: enum)
```

### Tool Availability ✓
```
[+] Available tools for AI: ['nmap', 'vulners', 'nmap-ftp-scripts', 
                             'nmap-smb-scripts', 'whatweb', 'dirb', 'nikto', 
                             'nuclei', 'wpscan', 'joomscan', 'sslyze', 'sqlmap', 
                             'enum4linux', 'ffuf']
```

### System State ✓
- All 4 initial scanners configured and ready
- Nikto parser integrated with proper enrichment
- AI prompt enhanced for cumulative analysis
- Master findings list properly accumulated
- Logging shows cumulative analysis in progress

## Usage

### Run with Default Configuration (Includes Nikto)
```bash
python orchestrator/main.py scanme.nmap.org --mode dynamic
```

This automatically runs: nmap → (whatweb + nuclei + nikto) → AI analysis

### Expected Output Flow
```
[~] Running initial group: ['nmap']
[~] Running initial group: ['whatweb', 'nuclei', 'nikto']

[*] Iteration 1: Collected 40+ findings
[AI] Analyzing 40+ cumulative findings from all scans...
[AI] Previously executed tools: {'nmap', 'whatweb', 'nuclei', 'nikto'}
[AI] Strategy: <holistic analysis explaining how findings relate>
[AI] Recommending X actions:
    - wpscan: Scan WordPress installation found on web server
    - nmap-ssh-scripts: Deep analysis of discovered SSH service
    - sqlmap: Test for SQL injection vulnerabilities
```

### Subsequent Iterations
Each iteration receives ALL previous + new findings, so recommendations improve with each round.

## Finding Enrichment

### Nikto Parser Maps to ASTRA Capabilities
| Nikto Finding | ASTRA Capability | Risk Level | Example |
|---|---|---|---|
| Directory indexing | directory_traversal | misconfig | Allows file browsing |
| Cookie flags missing | cookie_handling | enum | Session security issue |
| Server version disclosure | server_disclosure | enum | Reconnaissance data |
| CGI vulnerabilities | cgi_vulnerability | exploit | Remote code execution |
| SSL/TLS issues | ssl_config | enum | Weak encryption |
| Authentication weakness | auth_weakness | misconfig | Bypass potential |

## AI Reasoning Example

When AI receives findings from all 4 initial scanners:
- **Nmap findings**: Open ports, services, versions
- **WhatWeb findings**: Technologies, web frameworks, plugins
- **Nuclei findings**: Known vulnerabilities in detected software
- **Nikto findings**: Web server misconfigurations, weak headers

AI then generates reasoning like:
```
"We've discovered Apache 2.4.41 with PHP 7.4.3 and WordPress 5.x. The server 
has weak SSL configuration and CGI directory exposure. Combined with the known 
vulnerabilities in WordPress 5.x, we should scan with wpscan for plugin 
vulnerabilities and use nmap-ssl scripts for deeper analysis."
```

## Files Modified

1. **orchestrator/core/registry.py**
   - Enabled nikto: changed `"enabled": False` → `True`

2. **orchestrator/main.py**
   - Updated default scanners: added `nikto` to defaults

3. **orchestrator/core/ai/planning_agent.py**
   - Enhanced prompt for cumulative analysis
   - Added logging for cumulative findings count
   - Added logging for previously executed tools

4. **orchestrator/core/parsers.py**
   - Added `parse_nikto_txt()` function
   - Registered nikto in `PARSER_MAPPING`
   - Proper capability/risk_level enrichment

## Key Features

✅ **Intelligent Tool Chaining**: AI understands dependencies and relationships
✅ **Holistic Analysis**: Each round considers ALL previous findings
✅ **Progressive Discovery**: Vulnerabilities found in iteration 1 → deeper scanning in iteration 2+
✅ **Cumulative Knowledge**: AI learns and recommends smarter as more data arrives
✅ **Rich Metadata**: All findings tagged with capability, risk_level, severity
✅ **Secure Execution**: subprocess.Popen with shell=False, shlex parsing
✅ **Fallback System**: Default commands ensure reliability
✅ **Real API Integration**: Gemini 2.5 Flash for intelligent recommendations

## Next Steps

1. **Run End-to-End Test**: `python orchestrator/main.py scanme.nmap.org --mode dynamic`
2. **Verify Cumulative Analysis**: Check that AI mentions ALL tools in recommendations
3. **Observe Multi-Round Scanning**: Watch as each iteration discovers new vulnerabilities
4. **Review AI Reasoning**: See how findings are related and acted upon collectively

## Architecture Highlights

- **Modular Design**: Each scanner is independent, composable
- **Unified Data Model**: StandardFinding ensures consistency
- **AI-Driven Strategy**: No hardcoded rules, AI determines next actions
- **Streaming Output**: Real-time feedback as scanners run
- **Robust Parsing**: Handles multiple output formats (XML, JSON, text)
- **Rich Context**: Findings include port, service, version, OS when available

---

**Status**: ✅ **READY FOR PRODUCTION TESTING**

System is fully configured for cumulative, intelligent, multi-round security scanning with AI-driven discovery optimization.
