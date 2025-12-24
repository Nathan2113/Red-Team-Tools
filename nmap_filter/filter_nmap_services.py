#!/usr/bin/env python3

"""
Recommended Nmap Scan:
    nmap -sC -sV -p- <IP> -oA scan

Required inputs:
  - Nmap XML scan file (e.g. scan.xml)
      Generated with service detection enabled (-sC -sV recommended)
      Recommended to do -oA for all output types
  - Service rules YAML file (e.g. service.yml)
      Defines buckets, ports, service names, and regex patterns

Usage:
  python3 filter_nmap_services.py -x scan.xml -r service.yml [-o services]

Outputs (default: ./services/):
  - <bucket>_ips.txt           One file per service bucket

  Below outputs are for testing and further implementing the script, I will get to these eventually...
  - unknown_endpoints.txt      Detailed list of endpoints with no matching rule
  - unknown_ports_summary.txt  Grouped unknown ports/services for rule expansion
  - unknown_ips.txt            Hosts with no known services at all (will probably take out, not really useful)

Notes:
  - Rule order matters: first matching rule wins
  - Prefer service-name matches for strong fingerprints (e.g. ms-sql-s)
  - Prefer port-based rules for protocol services (e.g. WinRM)
  - Dynamic RPC and other known-noise endpoints are automatically suppressed
"""


from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

import yaml  # pip install pyyaml


def parse_nmap_xml(xml_path: Path):
    root = ET.parse(xml_path).getroot()

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            proto = port.get("protocol")
            portid = int(port.get("portid"))

            svc = port.find("service")
            yield {
                "ip": ip,
                "proto": proto,
                "port": portid,
                "service": (svc.get("name") or "").lower() if svc is not None else "",
                "product": (svc.get("product") or "").lower() if svc is not None else "",
                "extrainfo": (svc.get("extrainfo") or "").lower() if svc is not None else "",
                "tunnel": (svc.get("tunnel") or "").lower() if svc is not None else "",
            }


def _field_as_text(ep, field: str) -> str:
    val = ep.get(field, "")
    if isinstance(val, list):
        return " ".join(str(x) for x in val)
    return str(val)

def matches(rule, ep):
    # 1) service_names acts as a filter (if present)
    svc_names = rule.get("service_names")
    if svc_names is not None and len(svc_names) > 0:
        if ep.get("service") not in svc_names:
            return False

    # 2) ports acts as a filter (if present)
    ports = rule.get("ports")
    if ports is not None and len(ports) > 0:
        ok = False
        for p in ports:
            if ep.get("proto") == p.get("proto") and ep.get("port") == p.get("port"):
                ok = True
                break
        if not ok:
            return False

    # 3) regex acts as a filter (if present) â€” OR across conditions
    regex_conds = rule.get("regex")
    if regex_conds is not None and len(regex_conds) > 0:
        for cond in regex_conds:
            field = cond.get("field")
            pattern = cond.get("pattern")
            if not field or not pattern:
                continue
            text = _field_as_text(ep, field)
            if re.search(pattern, text, re.I):
                return True
        return False

    # 4) If rule only had service_names and/or ports and they passed, it's a match.
    return True


def is_dynamic_rpc(ep):
    return (
        ep.get("proto") == "tcp" and
        isinstance(ep.get("port"), int) and
        ep["port"] >= 49152 and
        ep.get("service") in ("msrpc", "ncacn_http", "ncacn_ip_tcp")
    )



def classify(ep, rules):
    # SSL override first
    svc = ep["service"]
    tun = ep["tunnel"]

    # Non-controversial SSL protocol upgrades
    if svc == "ldap" and tun == "ssl":
        return "ldaps"
    if svc == "imap" and tun == "ssl":
        return "imaps"
    if svc == "pop3" and tun == "ssl":
        return "pop3s"
    if svc == "smtp" and tun == "ssl":
        return "smtps"

    # YAML rules win first (ports, service names, regex)
    for rule in rules:
        if matches(rule, ep):
            return rule["bucket"]

    # Generic web classification LAST
    if svc == "https":
        return "https"
    if svc in ("http", "http-alt", "http-proxy") and tun == "ssl":
        return "https"
    if svc in ("http", "http-alt", "http-proxy"):
        return "http"

    return "unknown"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-x", "--xml", required=True, help="Nmap XML output")
    ap.add_argument("-r", "--rules", required=True, help="Service rules YAML")
    ap.add_argument("-o", "--out", default="services", help="Output folder (default: services)")
    args = ap.parse_args()

    rules = yaml.safe_load(Path(args.rules).read_text())["rules"]

    outdir = Path(args.out)
    outdir.mkdir(exist_ok=True)

    # bucket -> set(ip)
    buckets = defaultdict(set)

    # ip -> has any known service
    host_has_known = defaultdict(bool)

    # unknown endpoint outputs
    unknown_endpoints = []                  # list of "ip proto/port service product"
    unknown_port_counts = defaultdict(set)  # (proto, port, service) -> set(ips)

    # track hosts that look RPC-ish (for dynamic-port suppression)
    rpcish_hosts = set()

    # services we consider noise (not worth rules)
    NOISE_SERVICES = {"kpasswd5", "ncacn_http", "llmnr", "mc-nmf"}

    for ep in parse_nmap_xml(Path(args.xml)):
        ip = ep["ip"]
        bucket = classify(ep, rules)

        buckets[bucket].add(ip)

        # mark host as known if ANY endpoint matches a real bucket
        if bucket != "unknown":
            host_has_known[ip] = True

        # identify RPC-ish hosts
        svc_norm = (ep.get("service") or "").lower()
        if (
            (ep.get("proto") == "tcp" and ep.get("port") == 135)
            or svc_norm in ("msrpc", "ncacn_http", "ncacn_ip_tcp")
        ):
            rpcish_hosts.add(ip)

        # capture unknown endpoints for rule expansion (with suppression)
        if bucket == "unknown" and not is_dynamic_rpc(ep):
            proto = ep.get("proto", "?")
            port = ep.get("port", "?")
            svc = ep.get("service") or "-"
            svc_norm = svc.lower()
            product = ep.get("product") or "-"

            # suppress known-noise services
            if svc_norm in NOISE_SERVICES:
                continue

            # suppress high-port unknowns on RPC-ish hosts (dynamic/ephemeral)
            if (
                proto == "tcp"
                and isinstance(port, int)
                and port >= 49152
                and svc_norm in ("-", "")
                and ip in rpcish_hosts
            ):
                continue

            unknown_endpoints.append(f"{ip} {proto}/{port} {svc} {product}")
            unknown_port_counts[(proto, port, svc)].add(ip)

    # hosts with NO known services at all (optional)
    unknown_ips = {ip for ip, known in host_has_known.items() if not known}

    # write bucket files
    for bucket, ips in buckets.items():
        path = outdir / f"{bucket}_ips.txt"
        path.write_text("\n".join(sorted(ips)) + "\n")

    # write fully-unknown hosts (optional)
    if unknown_ips:
        path = outdir / "unknown_ips.txt"
        path.write_text("\n".join(sorted(unknown_ips)) + "\n")

    # write unknown endpoints (detailed)
    if unknown_endpoints:
        path = outdir / "unknown_endpoints.txt"
        path.write_text("\n".join(sorted(unknown_endpoints)) + "\n")

    # write unknown ports summary (grouped)
    if unknown_port_counts:
        lines = []
        for (proto, port, svc), ips in sorted(
            unknown_port_counts.items(),
            key=lambda x: (
                x[0][0],
                int(x[0][1]) if str(x[0][1]).isdigit() else 999999,
                x[0][2],
            ),
        ):
            lines.append(f"{proto}/{port} {svc} {len(ips)} hosts")
        path = outdir / "unknown_ports_summary.txt"
        path.write_text("\n".join(lines) + "\n")

    print(f"[+] Wrote {len(buckets)} service files to {outdir}/")
    if unknown_ips:
        print(f"[!] unknown_ips.txt contains {len(unknown_ips)} hosts")
    else:
        print("[+] No fully-unknown hosts found")

    if unknown_endpoints:
        print(f"[!] unknown_endpoints.txt contains {len(unknown_endpoints)} endpoints")
    else:
        print("[+] No unknown endpoints found")

    if unknown_port_counts:
        print(f"[!] unknown_ports_summary.txt contains {len(unknown_port_counts)} port/service groups")



if __name__ == "__main__":
    main()


