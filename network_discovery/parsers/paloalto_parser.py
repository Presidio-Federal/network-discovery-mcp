"""
Palo Alto PAN-OS configuration parser using TTP.
"""

import logging
from typing import Dict, Any
from ttp import ttp

from .base_parser import BaseParser, ParserResult

logger = logging.getLogger(__name__)


# TTP template for Palo Alto PAN-OS (SET format)
PALOALTO_TEMPLATE = """
<group name="system">
set deviceconfig system hostname {{ hostname }}
set deviceconfig system domain {{ domain }}
set deviceconfig system ip-address {{ ip_address }}
set deviceconfig system netmask {{ netmask }}
set deviceconfig system default-gateway {{ default_gateway }}
set deviceconfig system dns-setting servers primary {{ dns_primary }}
set deviceconfig system dns-setting servers secondary {{ dns_secondary }}
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address {{ ntp_server }}
</group>

<group name="zones">
set zone {{ zone_name }} network layer3 {{ interface }}
</group>

<group name="interfaces">
set network interface ethernet {{ interface }} layer3 ip {{ ip_address }}/{{ prefix_length }}
set network interface ethernet {{ interface }} comment {{ comment | re(".*") }}
set network interface ethernet {{ interface }} layer3 interface-management-profile {{ management_profile }}
</group>

<group name="virtual_routers">
set network virtual-router {{ vr_name }} interface {{ interface }}
set network virtual-router {{ vr_name }} routing-table ip static-route {{ route_name }} destination {{ destination }}
set network virtual-router {{ vr_name }} routing-table ip static-route {{ route_name }} nexthop ip-address {{ next_hop }}
set network virtual-router {{ vr_name }} protocol bgp enable yes
set network virtual-router {{ vr_name }} protocol bgp local-as {{ local_as }}
</group>

<group name="address_objects">
set address {{ object_name }} ip-netmask {{ ip_netmask }}
set address {{ object_name }} description {{ description | re(".*") }}
</group>

<group name="address_groups">
set address-group {{ group_name }} static {{ member }}
</group>

<group name="service_objects">
set service {{ service_name }} protocol {{ protocol }} port {{ port }}
set service {{ service_name }} description {{ description | re(".*") }}
</group>

<group name="security_policies">
set rulebase security rules {{ rule_name }} from {{ from_zone }}
set rulebase security rules {{ rule_name }} to {{ to_zone }}
set rulebase security rules {{ rule_name }} source {{ source }}
set rulebase security rules {{ rule_name }} destination {{ destination }}
set rulebase security rules {{ rule_name }} service {{ service }}
set rulebase security rules {{ rule_name }} application {{ application }}
set rulebase security rules {{ rule_name }} action {{ action }}
</group>

<group name="nat_policies">
set rulebase nat rules {{ rule_name }} from {{ from_zone }}
set rulebase nat rules {{ rule_name }} to {{ to_zone }}
set rulebase nat rules {{ rule_name }} source {{ source }}
set rulebase nat rules {{ rule_name }} destination {{ destination }}
set rulebase nat rules {{ rule_name }} service {{ service }}
set rulebase nat rules {{ rule_name }} source-translation dynamic-ip-and-port interface-address interface {{ interface }}
set rulebase nat rules {{ rule_name }} destination-translation translated-address {{ translated_address }}
</group>

<group name="administrator_accounts">
set mgt-config users {{ username }} permissions role-based {{ role }}
set mgt-config users {{ username }} password {{ password }}
</group>
"""


class PaloAltoParser(BaseParser):
    """Parser for Palo Alto PAN-OS configurations."""
    
    def get_parser_name(self) -> str:
        return "ttp"
    
    def get_parser_version(self) -> str:
        try:
            import ttp
            return ttp.__version__
        except:
            return "unknown"
    
    def parse(self, raw_config: str, hostname: str, ip: str) -> ParserResult:
        """
        Parse Palo Alto PAN-OS configuration using TTP.
        
        Args:
            raw_config: Raw CLI configuration (SET format)
            hostname: Device hostname
            ip: Device IP
            
        Returns:
            ParserResult: Parsed configuration
        """
        errors = []
        warnings = []
        
        try:
            # Parse with TTP
            parser = ttp(data=raw_config, template=PALOALTO_TEMPLATE)
            parser.parse()
            results = parser.result()[0][0] if parser.result() else {}
            
            # Post-process results
            structured_config = self._post_process_paloalto(results)
            
            # Extract hostname if available
            if "system" in structured_config and "hostname" in structured_config["system"]:
                hostname = structured_config["system"]["hostname"]
            
            logger.info(f"Successfully parsed Palo Alto PAN-OS config for {hostname}")
            
        except Exception as e:
            logger.error(f"Failed to parse Palo Alto config for {hostname}: {str(e)}")
            errors.append(f"Parsing failed: {str(e)}")
            structured_config = {"raw_config": raw_config}
        
        return self._create_result(
            hostname=hostname,
            ip=ip,
            vendor="Palo Alto",
            structured_config=structured_config,
            errors=errors,
            warnings=warnings
        )
    
    def _post_process_paloalto(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process parsed Palo Alto results."""
        structured = {}
        
        # System
        if "system" in results:
            structured["system"] = results["system"]
        
        # Zones
        if "zones" in results:
            zones = {}
            zone_list = results["zones"] if isinstance(results["zones"], list) else [results["zones"]]
            for zone in zone_list:
                if isinstance(zone, dict) and "zone_name" in zone:
                    name = zone["zone_name"]
                    zones[name] = {k: v for k, v in zone.items() if k != "zone_name"}
            structured["zones"] = zones
        
        # Interfaces
        if "interfaces" in results:
            interfaces = {}
            interface_list = results["interfaces"] if isinstance(results["interfaces"], list) else [results["interfaces"]]
            for intf in interface_list:
                if isinstance(intf, dict) and "interface" in intf:
                    name = intf["interface"]
                    interfaces[name] = {k: v for k, v in intf.items() if k != "interface"}
            structured["interfaces"] = interfaces
        
        # Virtual routers
        if "virtual_routers" in results:
            structured["virtual_routers"] = results["virtual_routers"]
        
        # Address objects
        if "address_objects" in results:
            address_objects = {}
            addr_list = results["address_objects"] if isinstance(results["address_objects"], list) else [results["address_objects"]]
            for addr in addr_list:
                if isinstance(addr, dict) and "object_name" in addr:
                    name = addr["object_name"]
                    address_objects[name] = {k: v for k, v in addr.items() if k != "object_name"}
            structured["address_objects"] = address_objects
        
        # Address groups
        if "address_groups" in results:
            structured["address_groups"] = results["address_groups"]
        
        # Service objects
        if "service_objects" in results:
            service_objects = {}
            svc_list = results["service_objects"] if isinstance(results["service_objects"], list) else [results["service_objects"]]
            for svc in svc_list:
                if isinstance(svc, dict) and "service_name" in svc:
                    name = svc["service_name"]
                    service_objects[name] = {k: v for k, v in svc.items() if k != "service_name"}
            structured["service_objects"] = service_objects
        
        # Security policies
        if "security_policies" in results:
            structured["security_policies"] = results["security_policies"]
        
        # NAT policies
        if "nat_policies" in results:
            structured["nat_policies"] = results["nat_policies"]
        
        # Administrator accounts
        if "administrator_accounts" in results:
            structured["administrator_accounts"] = results["administrator_accounts"]
        
        return structured

