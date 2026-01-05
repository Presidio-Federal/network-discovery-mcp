"""
Base parser interface for device configuration parsing.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional


@dataclass
class ParserResult:
    """Result of parsing a configuration."""
    
    hostname: str
    ip: str
    vendor: str
    model: str
    parsed_at: str
    parser: str
    parser_version: str
    
    structured_config: Dict[str, Any]
    parsing_errors: List[str] = field(default_factory=list)
    parsing_warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "vendor": self.vendor,
            "model": self.model,
            "parsed_at": self.parsed_at,
            "parser": self.parser,
            "parser_version": self.parser_version,
            "structured_config": self.structured_config,
            "parsing_errors": self.parsing_errors,
            "parsing_warnings": self.parsing_warnings,
        }


class BaseParser(ABC):
    """Base class for device configuration parsers."""
    
    def __init__(self, model: str = ""):
        """
        Initialize parser.
        
        Args:
            model: Device model (optional)
        """
        self.model = model
    
    @abstractmethod
    def parse(self, raw_config: str, hostname: str, ip: str) -> ParserResult:
        """
        Parse raw configuration into structured data.
        
        Args:
            raw_config: Raw CLI configuration text
            hostname: Device hostname
            ip: Device IP address
            
        Returns:
            ParserResult: Parsed configuration with metadata
        """
        pass
    
    @abstractmethod
    def get_parser_name(self) -> str:
        """Get the name of this parser."""
        pass
    
    @abstractmethod
    def get_parser_version(self) -> str:
        """Get the version of the parsing library."""
        pass
    
    def _create_result(
        self,
        hostname: str,
        ip: str,
        vendor: str,
        structured_config: Dict[str, Any],
        errors: List[str] = None,
        warnings: List[str] = None
    ) -> ParserResult:
        """
        Helper to create a ParserResult.
        
        Args:
            hostname: Device hostname
            ip: Device IP
            vendor: Device vendor
            structured_config: Parsed configuration
            errors: Parsing errors
            warnings: Parsing warnings
            
        Returns:
            ParserResult: Complete parser result
        """
        return ParserResult(
            hostname=hostname,
            ip=ip,
            vendor=vendor,
            model=self.model,
            parsed_at=datetime.utcnow().isoformat() + "Z",
            parser=self.get_parser_name(),
            parser_version=self.get_parser_version(),
            structured_config=structured_config,
            parsing_errors=errors or [],
            parsing_warnings=warnings or []
        )

