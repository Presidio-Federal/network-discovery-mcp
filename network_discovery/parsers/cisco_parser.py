"""
Cisco configuration parser using TTP (Template Text Parser).

Supports: IOS, IOS-XE, IOS-XR, NX-OS, ASA
"""

import logging
from typing import Dict, Any, List
from ttp import ttp

from .base_parser import BaseParser, ParserResult

logger = logging.getLogger(__name__)


# TTP template for Cisco IOS/IOS-XE configurations
CISCO_IOS_TEMPLATE = """
<group name="system">
hostname {{ hostname }}
</group>

<group name="interfaces">
interface {{ interface }}
 description {{ description | re(".*") }}
 ip address {{ ip_address }} {{ subnet_mask }}
 shutdown {{ shutdown | set(True) }}
 no shutdown {{ shutdown | set(False) }}
 switchport mode {{ switchport_mode }}
 switchport access vlan {{ access_vlan }}
 switchport trunk allowed vlan {{ trunk_vlans | re(".*") }}
 speed {{ speed }}
 duplex {{ duplex }}
 vrf forwarding {{ vrf }}
 ip ospf {{ ospf_process }} area {{ ospf_area }}
 channel-group {{ channel_group }} mode {{ channel_mode }}
</group>

<group name="vlans">
vlan {{ vlan_id }}
 name {{ vlan_name | re(".*") }}
</group>

<group name="ospf">
router ospf {{ process_id }}
 router-id {{ router_id }}
 network {{ network }} {{ wildcard }} area {{ area }}
 passive-interface {{ passive_interface }}
 default-information originate {{ default_originate | set(True) }}
</group>

<group name="bgp">
router bgp {{ asn }}
 bgp router-id {{ router_id }}
 neighbor {{ neighbor }} remote-as {{ remote_as }}
 neighbor {{ neighbor }} description {{ neighbor_description | re(".*") }}
 network {{ network }} mask {{ mask }}
</group>

<group name="static_routes">
ip route {{ destination }} {{ mask }} {{ next_hop }} {{ distance }}
ip route {{ destination }} {{ mask }} {{ next_hop }}
</group>

<group name="acls">
ip access-list {{ acl_type }} {{ acl_name }}
 {{ acl_sequence }} {{ action }} {{ protocol }} {{ source }} {{ source_wildcard }} {{ destination }} {{ destination_wildcard }} {{ options | re(".*") }}
 {{ acl_sequence }} {{ action }} {{ protocol }} {{ source }} {{ destination }} {{ options | re(".*") }}
 {{ action }} {{ protocol }} any any {{ options | re(".*") }}
</group>

<group name="ntp">
ntp server {{ ntp_server }}
</group>

<group name="dns">
ip name-server {{ dns_server }}
</group>

<group name="snmp">
snmp-server community {{ community }} {{ permission }}
snmp-server location {{ location | re(".*") }}
snmp-server contact {{ contact | re(".*") }}
snmp-server host {{ host }} version {{ version }} {{ community }}
</group>

<group name="users">
username {{ username }} privilege {{ privilege }} secret {{ secret_type }} {{ secret }}
username {{ username }} privilege {{ privilege }} password {{ password_type }} {{ password }}
</group>

<group name="aaa">
aaa new-model {{ aaa_new_model | set(True) }}
aaa authentication login {{ list_name }} {{ method1 }} {{ method2 }}
aaa authorization exec {{ list_name }} {{ method1 }} {{ method2 }}
</group>

<group name="logging">
logging {{ logging_server }}
logging facility {{ facility }}
logging trap {{ level }}
</group>

<group name="spanning_tree">
spanning-tree mode {{ mode }}
spanning-tree vlan {{ vlan }} priority {{ priority }}
</group>
"""

# TTP template for Cisco ASA configurations
CISCO_ASA_TEMPLATE = """
<group name="system">
hostname {{ hostname }}
</group>

<group name="interfaces">
interface {{ interface }}
 nameif {{ nameif }}
 security-level {{ security_level }}
 ip address {{ ip_address }} {{ subnet_mask }}
 description {{ description | re(".*") }}
 shutdown {{ shutdown | set(True) }}
 no shutdown {{ shutdown | set(False) }}
</group>

<group name="object_groups">
object-group network {{ name }}
 description {{ description | re(".*") }}
 network-object {{ network }} {{ mask }}
 network-object host {{ host }}
</group>

<group name="access_lists">
access-list {{ acl_name }} extended {{ action }} {{ protocol }} {{ source }} {{ destination }} {{ options | re(".*") }}
access-list {{ acl_name }} extended {{ action }} {{ protocol }} any any
</group>

<group name="nat_rules">
nat ({{ source_interface }},{{ destination_interface }}) source {{ source_type }} {{ source_obj }} {{ destination_type }} {{ destination_obj }}
</group>

<group name="static_routes">
route {{ interface }} {{ destination }} {{ mask }} {{ gateway }} {{ metric }}
route {{ interface }} {{ destination }} {{ mask }} {{ gateway }}
</group>
"""


class CiscoParser(BaseParser):
    """Parser for Cisco device configurations."""
    
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
        Parse Cisco configuration using TTP.
        
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
            # Determine if this is an ASA
            is_asa = "ASA" in self.model.upper() or "ASA Version" in raw_config
            
            # Select appropriate template
            template = CISCO_ASA_TEMPLATE if is_asa else CISCO_IOS_TEMPLATE
            
            # Parse with TTP
            parser = ttp(data=raw_config, template=template)
            parser.parse()
            results = parser.result()[0][0] if parser.result() else {}
            
            # Post-process: convert lists to proper structures
            structured_config = self._post_process_cisco(results, is_asa)
            
            # Extract hostname from parsed config if available
            if "system" in structured_config and "hostname" in structured_config["system"]:
                hostname = structured_config["system"]["hostname"]
            
            logger.info(f"Successfully parsed Cisco {'ASA' if is_asa else 'IOS'} config for {hostname}")
            
        except Exception as e:
            logger.error(f"Failed to parse Cisco config for {hostname}: {str(e)}")
            errors.append(f"Parsing failed: {str(e)}")
            structured_config = {"raw_config": raw_config}
        
        return self._create_result(
            hostname=hostname,
            ip=ip,
            vendor="Cisco",
            structured_config=structured_config,
            errors=errors,
            warnings=warnings
        )
    
    def _post_process_cisco(self, results: Dict[str, Any], is_asa: bool) -> Dict[str, Any]:
        """
        Post-process parsed results into a cleaner structure.
        
        Args:
            results: Raw TTP parsing results
            is_asa: Whether this is an ASA device
            
        Returns:
            Dict: Cleaned structured configuration
        """
        structured = {}
        
        # System info
        if "system" in results:
            structured["system"] = results["system"]
        
        # Interfaces - convert list to dict keyed by interface name
        if "interfaces" in results:
            interfaces = {}
            interface_list = results["interfaces"] if isinstance(results["interfaces"], list) else [results["interfaces"]]
            for intf in interface_list:
                if isinstance(intf, dict) and "interface" in intf:
                    name = intf["interface"]
                    interfaces[name] = {k: v for k, v in intf.items() if k != "interface"}
            structured["interfaces"] = interfaces
        
        # VLANs - convert list to dict keyed by VLAN ID
        if "vlans" in results and not is_asa:
            vlans = {}
            vlan_list = results["vlans"] if isinstance(results["vlans"], list) else [results["vlans"]]
            for vlan in vlan_list:
                if isinstance(vlan, dict) and "vlan_id" in vlan:
                    vid = vlan["vlan_id"]
                    vlans[vid] = {"name": vlan.get("vlan_name", f"VLAN{vid}")}
            structured["vlans"] = vlans
        
        # OSPF
        if "ospf" in results:
            structured["ospf"] = results["ospf"]
        
        # BGP
        if "bgp" in results:
            structured["bgp"] = results["bgp"]
        
        # Static routes
        if "static_routes" in results:
            structured["static_routes"] = results["static_routes"] if isinstance(results["static_routes"], list) else [results["static_routes"]]
        
        # ACLs
        if "acls" in results:
            structured["acls"] = results["acls"]
        
        # NTP servers
        if "ntp" in results:
            ntp_list = results["ntp"] if isinstance(results["ntp"], list) else [results["ntp"]]
            structured["ntp_servers"] = [n.get("ntp_server") for n in ntp_list if "ntp_server" in n]
        
        # DNS servers
        if "dns" in results:
            dns_list = results["dns"] if isinstance(results["dns"], list) else [results["dns"]]
            structured["dns_servers"] = [d.get("dns_server") for d in dns_list if "dns_server" in d]
        
        # SNMP
        if "snmp" in results:
            structured["snmp"] = results["snmp"]
        
        # Users
        if "users" in results:
            structured["users"] = results["users"]
        
        # AAA
        if "aaa" in results:
            structured["aaa"] = results["aaa"]
        
        # Logging
        if "logging" in results:
            structured["logging"] = results["logging"]
        
        # Spanning Tree
        if "spanning_tree" in results:
            structured["spanning_tree"] = results["spanning_tree"]
        
        # ASA-specific
        if is_asa:
            if "object_groups" in results:
                structured["object_groups"] = results["object_groups"]
            if "access_lists" in results:
                structured["access_lists"] = results["access_lists"]
            if "nat_rules" in results:
                structured["nat_rules"] = results["nat_rules"]
        
        return structured

