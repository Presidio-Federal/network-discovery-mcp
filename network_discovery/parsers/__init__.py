"""
Parsers module for converting raw CLI configs to structured data.
"""

from .base_parser import BaseParser, ParserResult
from .cisco_parser import CiscoParser
from .arista_parser import AristaParser
from .juniper_parser import JuniperParser
from .paloalto_parser import PaloAltoParser

__all__ = [
    "BaseParser",
    "ParserResult",
    "CiscoParser",
    "AristaParser",
    "JuniperParser",
    "PaloAltoParser",
]

# Parser registry - maps vendor names to parser classes
PARSER_REGISTRY = {
    "Cisco": CiscoParser,
    "Arista": AristaParser,
    "Juniper": JuniperParser,
    "Palo Alto": PaloAltoParser,
}

def get_parser(vendor: str, model: str = "") -> BaseParser:
    """
    Get the appropriate parser for a vendor.
    
    Args:
        vendor: Device vendor name
        model: Device model (optional, for vendor-specific handling)
        
    Returns:
        BaseParser: Parser instance for the vendor
        
    Raises:
        ValueError: If vendor is not supported
    """
    parser_class = PARSER_REGISTRY.get(vendor)
    if not parser_class:
        raise ValueError(f"No parser available for vendor: {vendor}")
    
    return parser_class(model=model)

