"""Azure (azurerm) rules."""

from __future__ import annotations

from ..evaluator import UNKNOWN
from ..model import Module, Resource, as_list
from . import Issue, Severity, rule
from ._common import exposure_for_specs, is_false, is_public_cidr, is_true

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


@rule(
    "AZ-STORAGE-001",
    "Storage account allows public blob containers",
    H,
    ["azurerm_storage_account"],
    """allow_nested_items_to_be_public = true lets any container in the
    account be switched to anonymous public read access.""",
    """allow_nested_items_to_be_public = false""",
    tags=["data-exposure"],
)
def storage_public(r: Resource, m: Module):
    for attr in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
        if is_true(r.config.get(attr)):
            yield Issue(f"{attr} is true", attr)


@rule(
    "AZ-STORAGE-002",
    "Storage account accepts plain HTTP",
    H,
    ["azurerm_storage_account"],
    """With HTTPS-only disabled, storage requests (including SAS tokens in the
    URL) can travel unencrypted.""",
    """https_traffic_only_enabled = true  # enable_https_traffic_only on azurerm < 4.0""",
    tags=["encryption"],
)
def storage_https(r: Resource, m: Module):
    for attr in ("https_traffic_only_enabled", "enable_https_traffic_only"):
        if is_false(r.config.get(attr)):
            yield Issue(f"{attr} is false", attr)


@rule(
    "AZ-STORAGE-003",
    "Storage account allows TLS versions older than 1.2",
    M,
    ["azurerm_storage_account"],
    """TLS 1.0 and 1.1 are deprecated and Azure is retiring support for them.""",
    """min_tls_version = "TLS1_2\"""",
    tags=["encryption"],
)
def storage_tls(r: Resource, m: Module):
    value = r.config.get("min_tls_version")
    if value in ("TLS1_0", "TLS1_1"):
        yield Issue(f"min_tls_version is {value}", "min_tls_version")


def _nsg_rules(r: Resource):
    if r.type == "azurerm_network_security_rule":
        yield None, r.config
    else:
        for i, sr in enumerate(r.blocks("security_rule")):
            yield f"security_rule[{i}]", sr


@rule(
    "AZ-NET-001",
    "Network security group allows inbound internet traffic to sensitive ports",
    H,
    ["azurerm_network_security_rule", "azurerm_network_security_group"],
    """An Allow rule from "*", "Internet" or 0.0.0.0/0 to SSH, RDP, WinRM or
    database ports exposes them to constant scanning and brute force. Rules
    that open every port are reported as critical.""",
    """Limit source_address_prefix to known ranges, and use Azure Bastion or
just-in-time VM access for administration.""",
    tags=["network"],
)
def nsg_open(r: Resource, m: Module):
    for path, sr in _nsg_rules(r):
        if str(sr.get("direction", "")).lower() != "inbound" or str(sr.get("access", "")).lower() != "allow":
            continue
        sources = as_list(sr.get("source_address_prefix")) + as_list(sr.get("source_address_prefixes"))
        public = [s for s in sources if is_public_cidr(s)]
        if not public:
            continue
        ports = as_list(sr.get("destination_port_range")) + as_list(sr.get("destination_port_ranges"))
        exp = exposure_for_specs(ports, sr.get("protocol"))
        if exp is None:
            continue
        name = sr.get("name")
        label = f'Rule "{name}"' if isinstance(name, str) else "Rule"
        yield Issue(
            f"{label} allows inbound from {', '.join(public)} to {exp.describe()}",
            path or "source_address_prefix",
            C if exp.all_ports else H,
        )


@rule(
    "AZ-SQL-001",
    "Database firewall rule allows the entire internet",
    H,
    [
        "azurerm_mssql_firewall_rule",
        "azurerm_sql_firewall_rule",
        "azurerm_postgresql_firewall_rule",
        "azurerm_postgresql_flexible_server_firewall_rule",
        "azurerm_mysql_firewall_rule",
        "azurerm_mysql_flexible_server_firewall_rule",
    ],
    """A firewall rule from 0.0.0.0 to 255.255.255.255 lets every IP address on
    the internet attempt to log in to the database server.""",
    """Allow only the client ranges that need access, or use private endpoints.""",
    tags=["network"],
)
def sql_firewall(r: Resource, m: Module):
    if r.config.get("start_ip_address") == "0.0.0.0" and r.config.get("end_ip_address") == "255.255.255.255":
        yield Issue("Firewall rule covers 0.0.0.0 - 255.255.255.255", "start_ip_address")


@rule(
    "AZ-KV-001",
    "Key Vault purge protection is disabled",
    L,
    ["azurerm_key_vault"],
    """Without purge protection, anyone with sufficient rights can permanently
    delete the vault and its keys during the soft-delete period, which can
    make encrypted data unrecoverable.""",
    """purge_protection_enabled = true""",
    tags=["resilience"],
)
def keyvault_purge(r: Resource, m: Module):
    value = r.config.get("purge_protection_enabled")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue("purge_protection_enabled is not true", "purge_protection_enabled" if value is not None else None)
