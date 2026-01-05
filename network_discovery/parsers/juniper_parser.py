"""
Juniper JUNOS configuration parser using TTP.
"""

import logging
from typing import Dict, Any
from ttp import ttp

from .base_parser import BaseParser, ParserResult

logger = logging.getLogger(__name__)


# TTP template for Juniper JUNOS (SET format)
JUNIPER_TEMPLATE = """
<group name="system">
set system host-name {{ hostname }}
set system domain-name {{ domain_name }}
</group>

<group name="interfaces">
set interfaces {{ interface }} unit {{ unit }} description {{ description | re(".*") }}
set interfaces {{ interface }} unit {{ unit }} family inet address {{ ip_address }}/{{ prefix_length }}
set interfaces {{ interface }} unit {{ unit }} family inet6 address {{ ipv6_address }}/{{ ipv6_prefix }}
set interfaces {{ interface }} unit {{ unit }} vlan-id {{ vlan_id }}
set interfaces {{ interface }} description {{ description | re(".*") }}
set interfaces {{ interface }} disable {{ disabled | set(True) }}
set interfaces {{ interface }} mtu {{ mtu }}
set interfaces {{ interface }} speed {{ speed }}
</group>

<group name="vlans">
set vlans {{ vlan_name }} vlan-id {{ vlan_id }}
set vlans {{ vlan_name }} description {{ description | re(".*") }}
set vlans {{ vlan_name }} l3-interface {{ l3_interface }}
</group>

<group name="routing_instances">
set routing-instances {{ instance_name }} instance-type {{ instance_type }}
set routing-instances {{ instance_name }} interface {{ interface }}
set routing-instances {{ instance_name }} route-distinguisher {{ route_distinguisher }}
set routing-instances {{ instance_name }} vrf-target {{ vrf_target }}
</group>

<group name="ospf">
set protocols ospf area {{ area }} interface {{ interface }}
set protocols ospf area {{ area }} interface {{ interface }} passive
</group>

<group name="bgp">
set protocols bgp group {{ group_name }} type {{ group_type }}
set protocols bgp group {{ group_name }} peer-as {{ peer_as }}
set protocols bgp group {{ group_name }} neighbor {{ neighbor }}
set protocols bgp local-as {{ local_as }}
</group>

<group name="static_routes">
set routing-options static route {{ destination }}/{{ prefix_length }} next-hop {{ next_hop }}
set routing-options static route {{ destination }}/{{ prefix_length }} qualified-next-hop {{ next_hop }} preference {{ preference }}
</group>

<group name="firewall">
set firewall family {{ family }} filter {{ filter_name }} term {{ term_name }} from {{ from_field }} {{ from_value }}
set firewall family {{ family }} filter {{ filter_name }} term {{ term_name }} then {{ action }}
</group>

<group name="ntp">
set system ntp server {{ ntp_server }}
</group>

<group name="dns">
set system name-server {{ dns_server }}
</group>

<group name="users">
set system login user {{ username }} class {{ class }}
set system login user {{ username }} authentication encrypted-password {{ password }}
</group>

<group name="snmp">
set snmp community {{ community }} authorization {{ permission }}
set snmp location {{ location | re(".*") }}
set snmp contact {{ contact | re(".*") }}
</group>
"""


class JuniperParser(BaseParser):
    """Parser for Juniper JUNOS configurations."""
    
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
        Parse Juniper JUNOS configuration using TTP.
        
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
            parser = ttp(data=raw_config, template=JUNIPER_TEMPLATE)
            parser.parse()
            results = parser.result()[0][0] if parser.result() else {}
            
            # Post-process results
            structured_config = self._post_process_juniper(results)
            
            # Extract hostname if available
            if "system" in structured_config and "hostname" in structured_config["system"]:
                hostname = structured_config["system"]["hostname"]
            
            logger.info(f"Successfully parsed Juniper JUNOS config for {hostname}")
            
        except Exception as e:
            logger.error(f"Failed to parse Juniper config for {hostname}: {str(e)}")
            errors.append(f"Parsing failed: {str(e)}")
            structured_config = {"raw_config": raw_config}
        
        return self._create_result(
            hostname=hostname,
            ip=ip,
            vendor="Juniper",
            structured_config=structured_config,
            errors=errors,
            warnings=warnings
        )
    
    def _post_process_juniper(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process parsed Juniper results."""
        structured = {}
        
        # System
        if "system" in results:
            structured["system"] = results["system"]
        
        # Interfaces - group by interface name and unit
        if "interfaces" in results:
            interfaces = {}
            interface_list = results["interfaces"] if isinstance(results["interfaces"], list) else [results["interfaces"]]
            for intf in interface_list:
                if isinstance(intf, dict) and "interface" in intf:
                    name = intf["interface"]
                    unit = intf.get("unit", "0")
                    full_name = f"{name}.{unit}" if unit != "0" else name
                    
                    if full_name not in interfaces:
                        interfaces[full_name] = {}
                    
                    interfaces[full_name].update({k: v for k, v in intf.items() if k not in ["interface", "unit"]})
            structured["interfaces"] = interfaces
        
        # VLANs
        if "vlans" in results:
            vlans = {}
            vlan_list = results["vlans"] if isinstance(results["vlans"], list) else [results["vlans"]]
            for vlan in vlan_list:
                if isinstance(vlan, dict) and "vlan_name" in vlan:
                    name = vlan["vlan_name"]
                    vlans[name] = {k: v for k, v in vlan.items() if k != "vlan_name"}
            structured["vlans"] = vlans
        
        # Routing instances (VRFs)
        if "routing_instances" in results:
            structured["routing_instances"] = results["routing_instances"]
        
        # OSPF
        if "ospf" in results:
            structured["ospf"] = results["ospf"]
        
        # BGP
        if "bgp" in results:
            structured["bgp"] = results["bgp"]
        
        # Static routes
        if "static_routes" in results:
            structured["static_routes"] = results["static_routes"] if isinstance(results["static_routes"], list) else [results["static_routes"]]
        
        # Firewall (ACLs)
        if "firewall" in results:
            structured["firewall"] = results["firewall"]
        
        # NTP
        if "ntp" in results:
            ntp_list = results["ntp"] if isinstance(results["ntp"], list) else [results["ntp"]]
            structured["ntp_servers"] = [n.get("ntp_server") for n in ntp_list if "ntp_server" in n]
        
        # DNS
        if "dns" in results:
            dns_list = results["dns"] if isinstance(results["dns"], list) else [results["dns"]]
            structured["dns_servers"] = [d.get("dns_server") for d in dns_list if "dns_server" in d]
        
        # Users
        if "users" in results:
            structured["users"] = results["users"]
        
        # SNMP
        if "snmp" in results:
            structured["snmp"] = results["snmp"]
        
        return structured

