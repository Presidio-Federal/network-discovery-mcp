"""
Arista EOS configuration parser using TTP.
"""

import logging
from typing import Dict, Any
from ttp import ttp

from .base_parser import BaseParser, ParserResult

logger = logging.getLogger(__name__)


# TTP template for Arista EOS (similar to IOS but with EOS-specific features)
ARISTA_EOS_TEMPLATE = """
<group name="system">
hostname {{ hostname }}
</group>

<group name="interfaces">
interface {{ interface }}
 description {{ description | re(".*") }}
 ip address {{ ip_address }}/{{ prefix_length }}
 ip address {{ ip_address }} {{ subnet_mask }}
 shutdown {{ shutdown | set(True) }}
 no shutdown {{ shutdown | set(False) }}
 switchport mode {{ switchport_mode }}
 switchport access vlan {{ access_vlan }}
 switchport trunk allowed vlan {{ trunk_vlans | re(".*") }}
 speed {{ speed }}
 mtu {{ mtu }}
 vrf {{ vrf }}
 channel-group {{ channel_group }} mode {{ channel_mode }}
</group>

<group name="vlans">
vlan {{ vlan_id }}
 name {{ vlan_name | re(".*") }}
 state {{ state }}
</group>

<group name="bgp">
router bgp {{ asn }}
 router-id {{ router_id }}
 neighbor {{ neighbor }} remote-as {{ remote_as }}
 neighbor {{ neighbor }} description {{ neighbor_description | re(".*") }}
 network {{ network }}/{{ prefix_length }}
 vrf {{ vrf_name }}
</group>

<group name="ospf">
router ospf {{ process_id }}
 router-id {{ router_id }}
 network {{ network }}/{{ prefix_length }} area {{ area }}
 network {{ network }} {{ wildcard }} area {{ area }}
 passive-interface {{ passive_interface }}
</group>

<group name="static_routes">
ip route {{ destination }}/{{ prefix_length }} {{ next_hop }} {{ distance }}
ip route {{ destination }}/{{ prefix_length }} {{ next_hop }}
ip route {{ destination }} {{ mask }} {{ next_hop }} {{ distance }}
ip route {{ destination }} {{ mask }} {{ next_hop }}
</group>

<group name="mlag">
mlag configuration {{ mlag_config | set(True) }}
 domain-id {{ domain_id }}
 local-interface {{ local_interface }}
 peer-address {{ peer_address }}
 peer-link {{ peer_link }}
</group>

<group name="ntp">
ntp server {{ ntp_server }}
</group>

<group name="dns">
ip name-server {{ dns_server }}
</group>

<group name="users">
username {{ username }} privilege {{ privilege }} role {{ role }} secret {{ secret_type }} {{ secret }}
username {{ username }} privilege {{ privilege }} secret {{ secret_type }} {{ secret }}
</group>

<group name="snmp">
snmp-server community {{ community }} {{ permission }}
snmp-server location {{ location | re(".*") }}
snmp-server contact {{ contact | re(".*") }}
snmp-server host {{ host }} version {{ version }} {{ community }}
</group>

<group name="acls">
ip access-list {{ acl_name }}
 {{ sequence }} {{ action }} {{ protocol }} {{ source }} {{ destination }} {{ options | re(".*") }}
</group>
"""


class AristaParser(BaseParser):
    """Parser for Arista EOS configurations."""
    
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
        Parse Arista EOS configuration using TTP.
        
        Args:
            raw_config: Raw CLI configuration
            hostname: Device hostname
            ip: Device IP
            
        Returns:
            ParserResult: Parsed configuration
        """
        errors = []
        warnings = []
        
        try:
            # Parse with TTP
            parser = ttp(data=raw_config, template=ARISTA_EOS_TEMPLATE)
            parser.parse()
            results = parser.result()[0][0] if parser.result() else {}
            
            # Post-process results
            structured_config = self._post_process_arista(results)
            
            # Extract hostname if available
            if "system" in structured_config and "hostname" in structured_config["system"]:
                hostname = structured_config["system"]["hostname"]
            
            logger.info(f"Successfully parsed Arista EOS config for {hostname}")
            
        except Exception as e:
            logger.error(f"Failed to parse Arista config for {hostname}: {str(e)}")
            errors.append(f"Parsing failed: {str(e)}")
            structured_config = {"raw_config": raw_config}
        
        return self._create_result(
            hostname=hostname,
            ip=ip,
            vendor="Arista",
            structured_config=structured_config,
            errors=errors,
            warnings=warnings
        )
    
    def _post_process_arista(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process parsed Arista results."""
        structured = {}
        
        # System
        if "system" in results:
            structured["system"] = results["system"]
        
        # Interfaces
        if "interfaces" in results:
            interfaces = {}
            interface_list = results["interfaces"] if isinstance(results["interfaces"], list) else [results["interfaces"]]
            for intf in interface_list:
                if isinstance(intf, dict) and "interface" in intf:
                    name = intf["interface"]
                    interfaces[name] = {k: v for k, v in intf.items() if k != "interface"}
            structured["interfaces"] = interfaces
        
        # VLANs
        if "vlans" in results:
            vlans = {}
            vlan_list = results["vlans"] if isinstance(results["vlans"], list) else [results["vlans"]]
            for vlan in vlan_list:
                if isinstance(vlan, dict) and "vlan_id" in vlan:
                    vid = vlan["vlan_id"]
                    vlans[vid] = {
                        "name": vlan.get("vlan_name", f"VLAN{vid}"),
                        "state": vlan.get("state", "active")
                    }
            structured["vlans"] = vlans
        
        # BGP
        if "bgp" in results:
            structured["bgp"] = results["bgp"]
        
        # OSPF
        if "ospf" in results:
            structured["ospf"] = results["ospf"]
        
        # Static routes
        if "static_routes" in results:
            structured["static_routes"] = results["static_routes"] if isinstance(results["static_routes"], list) else [results["static_routes"]]
        
        # MLAG (Arista-specific)
        if "mlag" in results:
            structured["mlag"] = results["mlag"]
        
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
        
        # ACLs
        if "acls" in results:
            structured["acls"] = results["acls"]
        
        return structured

