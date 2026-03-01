from typing import Callable, Dict, Optional

from .nmap import parse_nmap_xml
from .whatweb import parse_whatweb_json
from .nuclei import parse_nuclei_jsonl
from .nikto import parse_nikto_txt

# 5. The Parser Dispatcher (The Brain's Librarian)
# This mapping allows the engine to dynamically select the correct parser.
PARSER_MAPPING: Dict[str, Callable] = {
    "nmap": parse_nmap_xml,
    "whatweb": parse_whatweb_json,
    "nuclei": parse_nuclei_jsonl,
    "nikto": parse_nikto_txt,
    "vulners": parse_nmap_xml, # The vulners script outputs Nmap XML
}

def get_parser_for_tool(tool_name: str) -> Optional[Callable]:
    """
    Given a tool's name, this function returns the corresponding parser function.
    Returns None if no parser is defined for the tool.
    """
    return PARSER_MAPPING.get(tool_name)
