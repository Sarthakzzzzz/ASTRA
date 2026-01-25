# ASTRA Mental Model: Facts → Rules → Attack Paths

## Three Layers of Understanding

### 1️⃣ **Facts Layer** (What parsers emit)
Atomic, stable observations that scanners produce:
- `open_port(22, service=ssh)`
- `service_version(openssh, 6.6.1)`
- `web_service(http://45.33.32.156:80)`
- `technology(Apache, 2.4.7)`

**Key principle**: Facts are **never judgmental**. They're just what the tool found.

### 2️⃣ **Rules Layer** (What makes facts meaningful)
Transform facts into **exploitable conditions**:
- `service_version(openssh, 6.6.1) → SSH_VERSION_OUTDATED` (if CVE exists)
- `web_service(http://...) → WEB_SURFACE_EXPOSED` (actionable)
- `open_port(23, telnet) → CLEARTEXT_AUTH_EXPOSED` (exploitable)

**Key principle**: Rules determine **risk_level**:
- `"enum"` - reconnaissance only (open_port, general service detection)
- `"exploit"` - actionable vulnerability (outdated version with CVE, default creds, web service)
- `"critical"` - immediate compromise risk (RCE, auth bypass, data exposure)

### 3️⃣ **Graph Layer** (What attackers actually care about)
Attack paths chain from asset → exploitable finding → technique → impact

**Key principle**: Only `"exploit"` and `"critical"` findings appear in attack paths.

```
Asset: scanme.nmap.org
  ├─ [ENUM] open_port:22 (ssh)           ← NOT in attack paths
  ├─ [ENUM] open_port:80 (http)          ← NOT in attack paths  
  ├─ [EXPLOIT] web_service:80            ← YES, in attack paths
  │   ├─ Technique: Web Surface Enumeration
  │   └─ Impact: Identification of Web Attack Vectors
  └─ [CRITICAL] SSH_AUTH_PASSWORD        ← YES, in attack paths
      ├─ Technique: Password Brute Force
      └─ Impact: Remote Shell Access
```

## Current Implementation

### StandardFinding Schema
```python
@dataclass
class StandardFinding:
    source_tool: str        # "nmap", "nuclei", "whatweb"
    target: str             # IP, URL, hostname
    finding_type: str       # "open_port", "web_service", "vulnerability"
    finding_value: Any      # Port number, service name, CVE ID
    risk_level: str         # "enum", "exploit", "critical"
    details: Dict[str, Any] # Additional atomic facts
```

### Parser Output Examples

**Nmap Parser** emits:
1. `open_port(22, risk_level="enum", details={service: ssh, version: 6.6.1})`
2. `service_version(..., risk_level="enum", ...)`
3. `web_service(http://..., risk_level="exploit", ...)`

**Nuclei Parser** (future):
1. Vulnerability findings with `risk_level="exploit"` or `"critical"`

**WhatWeb Parser** (future):
1. Technology findings with `risk_level="enum"`
2. Misconfiguration with `risk_level="exploit"`

### Rule Matching Example
```yaml
- rule_name: "Trigger Nikto on HTTP services"
  triggers:
    - field: "finding_type"
      value: "web_service"           # Matches web_service findings
  action:
    tool_to_run: "nikto"
    technique: "Web Surface Enumeration"
    impact: "Identification of Web Attack Vectors"
```

### Graph Filtering
```python
def get_attack_paths():
    # Only include findings where risk_level in ["exploit", "critical"]
    # This filters out reconnaissance-only facts
    # Shows only actionable security states
```

## Migration Path

✅ **Phase 1 (Done)**: 
- Fixed finding schema with risk_level
- Updated nmap parser to emit atomic facts
- Graph filters by risk_level

🔄 **Phase 2 (Next)**:
- Update rules to properly classify findings
- Add service_version CVE matching
- Update other parsers (nuclei, whatweb)

🎯 **Phase 3 (Future)**:
- Separate enum graph from exploit graph
- Build MITRE ATT&CK chain connections
- Add impact scoring

## Key Differences from Raw Output

| What | Before | After |
|------|--------|-------|
| open_port findings in graph | Yes (raw scan data) | No (enum level) |
| web_service in graph | Yes (actionable) | Yes (exploit level) |
| Attack paths | Mixed with noise | Only exploitable states |
| Parser responsibility | Output everything | Classify by risk_level |
| Rule responsibility | Select findings | Assign exploitability |

## Testing

```bash
# See enriched findings (8 instead of 5)
python3 orchestrator/main.py scanme.nmap.org --mode dynamic --dry-run

# See attack paths filtered to only exploitable
# "Path 1: scanme.nmap.org → web_service"
```

---

**The System Now Has**:
- ✅ Brainstem: Facts layer (atomic observations)
- ✅ Basic reasoning: Rules layer (meaning assignment)
- 🔄 Frontal lobe: Attack paths (only exploitable chains)
