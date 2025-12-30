#!/usr/bin/env python3
"""
generate_krb5_conf.py

Generate a reproducible Kerberos (krb5.conf) configuration for Active Directory,
with optional /etc/hosts management for labs where DNS is unreliable.

Key Concepts
------------
- Realm ≠ Domain
  * Realm: Kerberos security boundary (UPPERCASE)  e.g. EXAMPLE.COM
  * Domain: DNS namespace (lowercase)              e.g. example.com

- Discovery vs Deterministic
  * Discovery (DNS-based):
      dns_lookup_kdc = true
      dns_lookup_realm = true
    Uses DNS SRV records; portable but DNS-dependent.

  * Deterministic (explicit):
      dns_lookup_kdc = false
      dns_lookup_realm = false
      Explicit [realms] and [domain_realm] entries
    Predictable across systems; recommended for labs.

  NOTE: Adding 'kdc = ...' alone is NOT deterministic unless DNS discovery
  is also disabled.

-----------------
- --dc-ip injects a managed /etc/hosts block to bypass broken DNS
- Automatically sets KDC/admin server to dc.<domain> if not provided
- Hosts and krb5.conf are backed up before modification

Safety & Usage
--------------
- Changes are atomic and idempotent
- --dry-run shows all changes without writing
- Verify behavior with:
    KRB5_TRACE=/dev/stderr kinit -V user@REALM




Examples:

  # DNS discovery only (no hardcoded KDCs, no hosts edits)
  sudo python3 generate_krb5_conf.py --realm EXAMPLE.COM --domain example.com

  # Deterministic-ish: specify KDCs/admin server (no hosts edits)
  sudo python3 generate_krb5_conf.py --realm EXAMPLE.COM --domain example.com \
    --kdc dc01.example.com --kdc dc02.example.com --admin-server dc01.example.com

  # Unreliable DNS: provide DC IP and it will add/update a managed /etc/hosts block.
  # If you omit --kdc/--admin-server, it will auto-set them to dc.<domain>
  sudo python3 generate_krb5_conf.py --realm EXAMPLE.COM --domain example.com --dc-ip <IP>

  # Custom DC hostname for hosts + explicit KDC/admin server
  sudo python3 generate_krb5_conf.py --realm EXAMPLE.COM --domain example.com \
    --dc-ip <IP> --dc-hostname dc.example.come \
    --kdc dc.example.com --admin-server dc.example.com

  # Write somewhere else (testing)
  python3 generate_krb5_conf.py --realm EXAMPLE.COM --domain example.com --out ./krb5.conf --dry-run
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import tempfile
from pathlib import Path


TEMPLATE = """[libdefaults]
  default_realm = {REALM}

  # Discovery (consistent across systems when DNS is correct)
  dns_lookup_kdc = {DNS_LOOKUP_KDC}
  dns_lookup_realm = {DNS_LOOKUP_REALM}

  # Reduce cross-distro inconsistencies
  rdns = {RDNS}
  dns_canonicalize_hostname = {DNS_CANONICALIZE}

  # Prefer TCP to avoid UDP fragmentation weirdness
  udp_preference_limit = 1

  # Reasonable defaults
  ticket_lifetime = 24h
  renew_lifetime = 7d
  forwardable = true
  proxiable = true

{REALMS_BLOCK}

[domain_realm]
  .{DOMAIN} = {REALM}
  {DOMAIN} = {REALM}

[logging]
  default = FILE:/var/log/krb5libs.log
  kdc = FILE:/var/log/krb5kdc.log
  admin_server = FILE:/var/log/kadmind.log
"""

HOSTS_BEGIN = "# --- managed by generate_krb5_conf.py (krb5) ---"
HOSTS_END = "# --- end managed by generate_krb5_conf.py (krb5) ---"


def normalize_realm(realm: str) -> str:
    # Kerberos realms are conventionally uppercase; this also avoids subtle mismatches.
    return realm.strip().upper()


def realms_block(realm: str, domain: str, kdcs: list[str], admin_server: str | None) -> str:
    # If no KDCs provided, omit the [realms] stanza entirely (DNS discovery can handle it).
    if not kdcs and not admin_server:
        return ""

    lines = ["[realms]", f"  {realm} = {{"]

    for kdc in kdcs:
        lines.append(f"    kdc = {kdc}")

    if admin_server:
        lines.append(f"    admin_server = {admin_server}")

    lines.append(f"    default_domain = {domain}")
    lines.append("  }")
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=str(path.parent), prefix=".krb5conf.", encoding="utf-8"
    ) as tf:
        tf.write(content)
        tmp_name = tf.name
    os.chmod(tmp_name, mode)
    os.replace(tmp_name, path)


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(path.name + f".bak_{ts}")
    backup.write_bytes(path.read_bytes())
    return backup


def update_hosts_file(hosts_path: Path, dc_ip: str, domain: str, dc_hostname: str) -> Path | None:
    """
    Idempotently manage a small block in /etc/hosts:
      <dc_ip> <dc_hostname> dc
      <dc_ip> <domain>

    - Creates/updates a marked block.
    - Backs up the existing hosts file if changes are made.
    """
    hosts_path = Path(hosts_path)

    if not hosts_path.exists():
        hosts_path.write_text("", encoding="utf-8")

    original = hosts_path.read_text(encoding="utf-8")

    block_lines = [
        f"{dc_ip} {dc_hostname} dc {domain}",
        "",
    ]
    new_block = "\n".join(block_lines)

    block_re = re.compile(
        rf"{re.escape(HOSTS_BEGIN)}.*?{re.escape(HOSTS_END)}\n?",
        re.DOTALL,
    )

    if block_re.search(original):
        updated = block_re.sub(new_block, original)
    else:
        sep = "" if (original == "" or original.endswith("\n")) else "\n"
        updated = original + sep + new_block

    if updated == original:
        return None  # already up-to-date

    # Backup hosts before writing
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = hosts_path.with_name(hosts_path.name + f".bak_{ts}")
    backup.write_bytes(hosts_path.read_bytes())

    atomic_write(hosts_path, updated, mode=0o644)
    return backup


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Generate krb5.conf from a template and optionally manage /etc/hosts for DC resolution."
    )
    ap.add_argument("--realm", required=True, help="Kerberos realm (e.g., EXAMPLE.COM)")
    ap.add_argument("--domain", required=True, help="DNS domain (e.g., example.com)")

    ap.add_argument("--kdc", action="append", default=[], help="KDC hostname/FQDN (repeatable)")
    ap.add_argument("--admin-server", help="Admin server hostname/FQDN (often a DC)")

    ap.add_argument("--dns-lookup-kdc", choices=["true", "false"], default="true")
    ap.add_argument("--dns-lookup-realm", choices=["true", "false"], default="true")
    ap.add_argument("--rdns", choices=["true", "false"], default="false")
    ap.add_argument("--dns-canonicalize", choices=["true", "false"], default="false")

    ap.add_argument(
        "--dc-ip",
        help="DC IP to add to /etc/hosts. If set, hosts will be updated unless --no-hosts is used.",
    )
    ap.add_argument(
        "--dc-hostname",
        help="DC hostname to map in /etc/hosts (default: dc.<domain>)",
    )
    ap.add_argument(
        "--hosts-path",
        default="/etc/hosts",
        help="Hosts file path (default: /etc/hosts)",
    )
    ap.add_argument(
        "--no-hosts",
        action="store_true",
        help="Do not modify hosts file even if --dc-ip is provided",
    )

    ap.add_argument("--out", default="/etc/krb5.conf", help="Output path (default: /etc/krb5.conf)")
    ap.add_argument("--no-backup", action="store_true", help="Do not back up an existing krb5.conf")
    ap.add_argument("--dry-run", action="store_true", help="Print result, do not write")
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    realm = normalize_realm(args.realm)
    domain = args.domain.strip().lower()

    kdcs = [k.strip() for k in args.kdc if k.strip()]
    admin_server = args.admin_server.strip() if args.admin_server else None

    dc_ip = args.dc_ip.strip() if args.dc_ip else None
    dc_hostname = (args.dc_hostname.strip().lower() if args.dc_hostname else f"dc.{domain}")

    # if user provides --dc-ip but omits --kdc/--admin-server,
    # assume the DC hostname is the KDC/admin server.
    if dc_ip and not kdcs:
        kdcs = [dc_hostname]
    if dc_ip and not admin_server:
        admin_server = dc_hostname

    realms = realms_block(realm=realm, domain=domain, kdcs=kdcs, admin_server=admin_server)

    content = TEMPLATE.format(
        REALM=realm,
        DOMAIN=domain,
        DNS_LOOKUP_KDC=args.dns_lookup_kdc,
        DNS_LOOKUP_REALM=args.dns_lookup_realm,
        RDNS=args.rdns,
        DNS_CANONICALIZE=args.dns_canonicalize,
        REALMS_BLOCK=realms.rstrip(),  # avoid extra blank lines if empty
    ).rstrip() + "\n"

    out_path = Path(args.out)

    if args.dry_run:
        print(content)
        if dc_ip and not args.no_hosts:
            print(f"\n# (dry-run) Would update {args.hosts_path} with:")
            print(f"#   {dc_ip} {dc_hostname} dc")
            print(f"#   {dc_ip} {domain}")
        return 0

    # Update hosts first (so the newly written krb5.conf can immediately work)
    if dc_ip and not args.no_hosts:
        backup = update_hosts_file(Path(args.hosts_path), dc_ip=dc_ip, domain=domain, dc_hostname=dc_hostname)
        if backup:
            print(f"[+] Updated {args.hosts_path} (backup: {backup})")
        else:
            print(f"[+] {args.hosts_path} already up to date")

    if not args.no_backup:
        backup = backup_existing(out_path)
        if backup:
            print(f"[+] Backed up existing {out_path} -> {backup}")

    atomic_write(out_path, content)
    print(f"[+] Wrote {out_path}")
    print("[+] Test config file with 'KRB5_TRACE=/dev/stderr kinit -V user@REALM' (REALM needs to be all uppercase)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

