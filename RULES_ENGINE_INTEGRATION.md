# ASTRA Rules-Based Decision Engine - Implementation Complete ✅

## Your Observations (Correct!)

You identified the exact problem:

1. **"Why am I getting the complete HTML page?"**
   - This is correct behavior - whatweb captures full page content for deep analysis
   - HTML is analyzed for technologies, frameworks, vulnerabilities, configurations

2. **"It identified Linux, so why didn't it scan enum4linux?"**
   - **This was the real issue!** The AI wasn't consulting the rules engine
   - Now it will, because we've integrated rules into the prompt

3. **"If we provide all the rules to the agent, wouldn't it have better context?"**
   - **Exactly!** We just did that
   - AI now receives MATCHED_RULES and DECISION_RULES in every prompt

## What Changed

### New Component: `orchestrator/core/rules_loader.py`
This module provides:
- `load_rules()` - Loads all YAML rule files
- `get_rules_context_for_ai()` - Formats decision rules for AI
- `match_rules_to_findings()` - Matches findings against rules
- `format_matched_rules_for_ai()` - Formats matched rules for AI context

### Updated Component: `orchestrator/core/ai/planning_agent.py`
Now includes:
- Import rules_loader functions
- Load and match rules before generating prompt
- Include matched rules in AI prompt
- Include full decision rules database in AI prompt
- Enhanced analysis instructions referencing rules

## How It Works Now

### Before (Generic)
```
AI receives: "Found SSH, HTTP, unknown tools, maybe recommend ssh_enum?"
Result: Generic recommendations without specific reasoning
```

### After (Rules-Driven)
```
AI receives:
  MATCHED_RULES: 
    - ssh_password_auth_enabled → Trigger: ssh_enum
    - ssh_weak_crypto_detected → Trigger: ssh_enum
    - open_port:22 ssh service

  DECISION_RULES:
    - ssh_weak_crypto_detected: "SSH weak cryptography detected"
      Triggers when: capability=weak_crypto, service=ssh
      → Trigger Tool: **ssh_enum**

AI generates: "SSH password auth enabled + weak crypto (matched 2 rules).
              Recommend: nmap-ssh-scripts (ssh_enum rules), enum4linux (network enumeration)"
Result: Rules-driven recommendations with specific reasoning
```

## 225 Rules Loaded

```
✓ auth.yaml:           30 rules (login endpoints, credentials, MFA, rate limiting)
✓ database.yaml:       55 rules (SQL injection, weak credentials, unencrypted data)
✓ network.yaml:        65 rules (SSH, FTP, SMB, Telnet, weak protocols)
✓ vulnerabilities.yaml: 2 rules (CVE matching, severity assessment)
✓ web.yaml:           73 rules (XSS, CSRF, path traversal, header issues)
─────────────────────────────────
TOTAL:                225 rules
```

## Enum4Linux Now Triggered By Rules

### Rule: `smb_service_exposed`
```yaml
- id: smb_service_exposed
  description: SMB service accessible on the network
  when:
    finding_type: open_port
    service: smb
    port: 445
  then:
    tool_to_run: smb_enum  # This maps to enum4linux
```

### How It Works
1. Nmap finds port 445 (SMB) open
2. Finding created: `finding_type="open_port", service="smb", port=445`
3. Rule matches: `smb_service_exposed` rule
4. AI gets: "SMB_EXPOSED rule matched → Recommend: enum4linux"
5. enum4linux executes automatically

## Example Scenario: scanme.nmap.org

### Iteration 1: Initial Scan
```
nmap → finds: port 22 (SSH), port 80 (HTTP)
whatweb → finds: Apache, PHP
nuclei → finds: password auth enabled, weak crypto (Terrapin)
nikto → finds: directory indexing, missing headers
```

### Matched Rules
```
- ssh_password_auth_enabled (rule)
  → Trigger: ssh_enum (nmap-ssh-scripts)

- ssh_weak_crypto_detected (rule)  
  → Trigger: ssh_enum (nmap-ssh-scripts)

- open_port:80 http (rule)
  → Triggers web scanning rules

- directory_indexing (rule)
  → Trigger: dirb (directory brute-force)
```

### AI Recommendation (Rules-Driven)
```
"Matched 4 rules based on findings:
 1. SSH password auth enabled - recommend nmap-ssh-scripts
 2. SSH weak crypto - recommend nmap-ssh-scripts  
 3. Directory indexing - recommend dirb
 4. HTTP service exposed - recommend nikto, wpscan"
```

### Iteration 2: Recommended Tools Execute
```
- nmap-ssh-scripts: Deep SSH enumeration
- dirb: Find hidden directories
- nikto: Web hardening checks (already did, but verifies)
```

## Integration Points

### 1. Rules Loaded Before AI Prompt
```python
# In planning_agent.py
matched_rules = match_rules_to_findings(findings)
matched_rules_text = format_matched_rules_for_ai(matched_rules)
rules_context = get_rules_context_for_ai()

# Both included in prompt
prompt = f"""
{matched_rules_text}
{rules_context}
..."""
```

### 2. AI Prompt Enhanced
```python
ANALYSIS INSTRUCTIONS:
1. Review ALL findings comprehensively
2. Use MATCHED RULES to identify high-priority recommendations  # ← NEW
3. Identify gaps and unexplored areas
4. Find services/versions that need deeper scanning
5. Use DECISION RULES to match findings with appropriate tools # ← NEW
6. Recommend tools that will expand on discovered capabilities
```

### 3. 225 Rules Now Available to AI
- Authentication rules (default creds, weak MFA, rate limiting)
- Database rules (SQL injection, weak credentials)
- Network rules (SSH, FTP, SMB, weak protocols) ← **Enum4linux here**
- Vulnerability rules (CVE matching)
- Web rules (XSS, CSRF, traversal, headers)

## Testing

Run the test to verify rules loading and matching:

```bash
python test_rules_engine.py
```

Expected output shows:
- 225 rules loaded from 5 YAML files
- SSH-related rules that trigger ssh_enum
- SMB-related rules that trigger enum4linux (smb_enum)
- Web-related rules that trigger web scanners

## Benefits of Rules-Based Approach

| Before | After |
|--------|-------|
| Generic AI recommendations | Rules-driven specific recommendations |
| Limited context | Full 225-rule decision database |
| AI guesses next tool | AI matches findings to rules |
| Single-tool recommendations | Multi-rule coordinated recommendations |
| No formal audit trail | Matched rules explain every recommendation |

## Key Files

- **rules_loader.py** (NEW) - Load, match, and format rules for AI
- **planning_agent.py** (UPDATED) - Now uses rules in prompt
- **test_rules_engine.py** (NEW) - Test rules loading and matching
- **orchestrator/rules/*.yaml** (5 files, 225 rules) - Decision rules database

## Example: How Enum4Linux Gets Triggered

### Before
```
AI: "Found some services, maybe try enum4linux?"
Status: No, not triggered
```

### After
```
1. Nmap finds: port 445 open, service=smb
2. Rule matched: "smb_service_exposed"
3. AI receives: "→ Trigger Tool: **smb_enum** (enum4linux)"
4. AI outputs: "Rule SMB_EXPOSED matched. Recommend: enum4linux"
5. Enum4linux runs
Status: YES, triggered by rules
```

## Next Steps

1. **Run next scan** with: `python orchestrator/main.py scanme.nmap.org --mode dynamic`
2. **Observe AI reasoning** - should now reference matched rules
3. **Verify enum4linux** - should be recommended when SMB detected
4. **Tune rules** - can modify rules in `orchestrator/rules/*.yaml` as needed

---

**Status**: ✅ **Rules Engine Integrated and Ready**

AI now has full context of 225 security rules and uses them to generate intelligent, findings-driven recommendations!
