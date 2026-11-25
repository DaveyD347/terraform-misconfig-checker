"""Google Cloud rules."""

from __future__ import annotations

from ..evaluator import UNKNOWN, is_unknown
from ..model import Module, Resource, as_list
from . import Issue, Severity, rule
from ._common import exposure_for_specs, is_false, is_public_cidr, is_true

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def _members(r: Resource) -> list[str]:
    return [x for x in as_list(r.config.get("member")) + as_list(r.config.get("members")) if isinstance(x, str)]


@rule(
    "GCP-STORAGE-001",
    "Cloud Storage bucket is publicly accessible",
    H,
    [
        "google_storage_bucket_iam_member",
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_access_control",
        "google_storage_default_object_access_control",
        "google_storage_bucket_acl",
    ],
    """Granting a role to allUsers or allAuthenticatedUsers makes the bucket
    readable (or writable) by anyone with a Google account or no account at
    all.""",
    """Grant roles to specific users, groups or service accounts. Enable
public access prevention on the bucket:

    public_access_prevention = "enforced\"""",
    tags=["data-exposure"],
)
def gcs_public(r: Resource, m: Module):
    public = [x for x in _members(r) if x in _PUBLIC_MEMBERS]
    entity = r.config.get("entity")
    if isinstance(entity, str) and entity in _PUBLIC_MEMBERS:
        public.append(entity)
    for entry in as_list(r.config.get("role_entity")):
        if isinstance(entry, str) and entry.split(":", 1)[-1] in _PUBLIC_MEMBERS:
            public.append(entry)
    if public:
        role = r.config.get("role")
        role_text = f" {role}" if isinstance(role, str) else ""
        yield Issue(f"Grants{role_text} to {', '.join(public)}", "members" if "members" in r.config else "member")


@rule(
    "GCP-STORAGE-002",
    "Cloud Storage bucket does not use uniform bucket-level access",
    L,
    ["google_storage_bucket"],
    """With fine-grained ACLs, individual objects can be made public even when
    bucket IAM looks locked down. Uniform bucket-level access makes IAM the
    only access control.""",
    """uniform_bucket_level_access = true""",
    tags=["data-exposure"],
)
def gcs_uniform(r: Resource, m: Module):
    value = r.config.get("uniform_bucket_level_access")
    if not is_true(value) and value is not UNKNOWN:
        yield Issue(
            "uniform_bucket_level_access is not true", "uniform_bucket_level_access" if value is not None else None
        )


@rule(
    "GCP-NET-001",
    "Firewall rule allows internet traffic to sensitive ports",
    H,
    ["google_compute_firewall"],
    """An ingress rule from 0.0.0.0/0 to SSH, RDP or database ports exposes
    every matching instance to the internet. Rules that allow every port are
    reported as critical.""",
    """Restrict source_ranges, and use Identity-Aware Proxy TCP forwarding
(35.235.240.0/20) for SSH and RDP.""",
    tags=["network"],
)
def firewall_open(r: Resource, m: Module):
    direction = r.config.get("direction") or "INGRESS"
    if direction != "INGRESS" or is_true(r.config.get("disabled")):
        return
    public = [s for s in as_list(r.config.get("source_ranges")) if is_public_cidr(s)]
    if not public:
        return
    for i, allow in enumerate(r.blocks("allow")):
        proto = allow.get("protocol")
        ports = as_list(allow.get("ports"))
        if proto in ("all",) or (not ports and proto in ("tcp", "udp", "sctp")):
            exp = exposure_for_specs(["*"], proto)
        else:
            exp = exposure_for_specs(ports, proto)
        if exp is not None:
            yield Issue(
                f"Allows {proto} from {', '.join(public)} to {exp.describe()}",
                f"allow[{i}]",
                C if exp.all_ports else H,
            )


def _ip_config(r: Resource) -> tuple[str | None, dict]:
    for i, settings in enumerate(r.blocks("settings")):
        for j, ipc in enumerate(settings.get("ip_configuration") or []):
            if isinstance(ipc, dict):
                return f"settings[{i}].ip_configuration[{j}]", ipc
    return None, {}


@rule(
    "GCP-SQL-001",
    "Cloud SQL instance is open to the internet",
    H,
    ["google_sql_database_instance"],
    """An authorized network of 0.0.0.0/0 lets any IP address connect to the
    instance's public IP and try to log in.""",
    """Remove the 0.0.0.0/0 authorized network; use private IP or the Cloud SQL
Auth Proxy instead.""",
    tags=["network"],
)
def sql_open(r: Resource, m: Module):
    path, ipc = _ip_config(r)
    for k, net in enumerate(ipc.get("authorized_networks") or []):
        if isinstance(net, dict) and is_public_cidr(net.get("value")):
            yield Issue(
                f"Authorized network {net.get('value')} allows the whole internet", f"{path}.authorized_networks[{k}]"
            )


_SSL_ENFORCED = ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")


@rule(
    "GCP-SQL-002",
    "Cloud SQL instance does not require SSL",
    M,
    ["google_sql_database_instance"],
    """Unless SSL is enforced, clients can connect to the public IP over an
    unencrypted connection.""",
    """settings {
      ip_configuration {
        ssl_mode = "ENCRYPTED_ONLY"
      }
    }""",
    tags=["encryption"],
)
def sql_ssl(r: Resource, m: Module):
    path, ipc = _ip_config(r)
    if path is None or is_false(ipc.get("ipv4_enabled", True)):
        return  # private IP only
    mode = ipc.get("ssl_mode")
    if mode is UNKNOWN or ipc.get("require_ssl") is UNKNOWN:
        return
    if mode in _SSL_ENFORCED or is_true(ipc.get("require_ssl")):
        return
    yield Issue("Public IP is enabled and SSL is not enforced", path)


_PRIMITIVE_ROLES = ("roles/owner", "roles/editor")
_PROJECT_IAM = [
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_folder_iam_member",
    "google_folder_iam_binding",
    "google_organization_iam_member",
    "google_organization_iam_binding",
]


@rule(
    "GCP-IAM-001",
    "Project or organization IAM grants a role to the public",
    C,
    _PROJECT_IAM,
    """Granting any role on a project, folder or organization to allUsers or
    allAuthenticatedUsers gives that access to everyone with (or without) a
    Google account.""",
    """Grant the role to specific identities instead.""",
    tags=["iam", "data-exposure"],
)
def project_public(r: Resource, m: Module):
    public = [x for x in _members(r) if x in _PUBLIC_MEMBERS]
    if public:
        yield Issue(
            f"Grants {r.config.get('role')} to {', '.join(public)}", "members" if "members" in r.config else "member"
        )


@rule(
    "GCP-IAM-002",
    "Primitive owner or editor role is granted",
    M,
    _PROJECT_IAM,
    """The basic Owner and Editor roles include thousands of permissions across
    every service. Google recommends predefined or custom roles instead.""",
    """Replace roles/owner and roles/editor with predefined roles scoped to the
services the identity uses.""",
    tags=["iam", "least-privilege"],
)
def primitive_roles(r: Resource, m: Module):
    role = r.config.get("role")
    if role in _PRIMITIVE_ROLES:
        yield Issue(f"Grants {role}", "role")


@rule(
    "GCP-COMPUTE-001",
    "Instance uses the default service account with full API access",
    M,
    ["google_compute_instance", "google_compute_instance_template"],
    """The Compute Engine default service account has the Editor role in many
    projects. Combined with the cloud-platform scope, any code running on the
    VM can manage most of the project.""",
    """Create a dedicated service account with only the roles the workload
needs, and attach it with that email.""",
    tags=["iam", "credentials"],
)
def default_sa(r: Resource, m: Module):
    for i, sa in enumerate(r.blocks("service_account")):
        email = sa.get("email")
        if is_unknown(email):
            continue
        default = email in (None, "", "default") or (
            isinstance(email, str) and email.endswith("-compute@developer.gserviceaccount.com")
        )
        scopes = as_list(sa.get("scopes"))
        if default and any(s in ("cloud-platform", "https://www.googleapis.com/auth/cloud-platform") for s in scopes):
            yield Issue("Default service account with the cloud-platform scope", f"service_account[{i}]")
