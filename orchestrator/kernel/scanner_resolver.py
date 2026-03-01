"""
Handles dependency resolution, tool selection, and binary checking.
"""
from typing import List
from . import scanner_registry as registry # Imports SCANNERS and TOOL_BINARIES from registry.py

def get_scanner_by_name(name: str):
    """Finds a scanner's configuration dictionary by its name."""
    for sc in registry.SCANNERS:
        if sc['name'] == name:
            return sc
    return None

def resolve_enabled_scanners(enable_arg: str) -> List[str]:
    """Resolves the --enable argument into a list of scanner names."""
    if not enable_arg or not enable_arg.strip():
        # Return default enabled scanners if arg is empty
        return [sc['name'] for sc in registry.SCANNERS if sc.get('enabled', False)]
    
    arg = enable_arg.lower().strip()
    if arg == 'all':
        return [sc['name'] for sc in registry.SCANNERS]
        
    requested = {n.strip() for n in enable_arg.split(',') if n.strip()}
    
    # Ensure nmap is implicitly enabled if any other tool depends on it
    needs_nmap = any(
        'nmap' in (get_scanner_by_name(name).get('depends_on') or []) for name in requested
    )
    if needs_nmap:
        requested.add('nmap')
        
    return [sc['name'] for sc in registry.SCANNERS if sc['name'] in requested]

def build_execution_groups(enabled_names: List[str]) -> List[List[str]]:
    """Builds a list of execution groups based on tool dependencies."""
    remaining = set(enabled_names)
    groups = []
    
    while remaining:
        ready = []
        for name in list(remaining):
            scanner = get_scanner_by_name(name)
            if not scanner: continue
            
            deps = scanner.get('depends_on', [])
            # Check if all dependencies are satisfied (i.e., not in the remaining set)
            if all(dep not in remaining for dep in deps):
                ready.append(name)
        
        if not ready:
            # Circular dependency detected
            raise RuntimeError(f"Could not resolve dependencies. Possible circular dependency in: {remaining}")
            
        groups.append(sorted(ready))
        remaining.difference_update(ready)
        
    return groups

