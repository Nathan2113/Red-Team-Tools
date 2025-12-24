#!/usr/bin/env python3
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

    # 3) regex acts as a filter (if present) — OR across conditions
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

    buckets = defaultdict(set)

    for ep in parse_nmap_xml(Path(args.xml)):
        bucket = classify(ep, rules)
        buckets[bucket].add(ep["ip"])

    for bucket, ips in buckets.items():
        path = outdir / f"{bucket}_ips.txt"
        path.write_text("\n".join(sorted(ips)) + "\n")

    print(f"[+] Wrote {len(buckets)} service files to {outdir}/")
    if "unknown" in buckets:
        print(f"[!] unknown_ips.txt contains {len(buckets['unknown'])} hosts")


if __name__ == "__main__":
    main()


