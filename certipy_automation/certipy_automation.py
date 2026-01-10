#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
import subprocess
import os


@dataclass(frozen=True)
class RunPaths:
    run_dir: Path
    raw_out: Path
    parsed_out: Path
    meta_out: Path
    json_out: Path


@dataclass(frozen=True)
class Args:
    username: str
    password: str | None
    kerberos: bool
    domain: str
    dc_ip: str
    target: str | None
    base_out: Path
    run_id: str
    paths: RunPaths
    


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value!r}")


def sanitize_domain_for_filename(domain: str) -> str:
    domain = domain.strip()
    if not domain:
        raise ValueError("domain is empty")

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", domain)
    safe = safe.strip(" ._")

    if not safe:
        raise ValueError("domain sanitizes to an empty filename stem")

    return safe


def default_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run-folder scaffolding + JSON parsing for certificate template findings."
    )
    p.add_argument("-u", "--username", required=True, help="Username")
    p.add_argument("-d", "--domain", required=True, help="Domain (e.g., corp.example.com)")
    p.add_argument("--dc-ip", required=True, type=validate_ip, help="Domain Controller IP (v4 or v6)")
    p.add_argument("--target", default=None, help="Target host for Kerberos mode (e.g., dc01.corp.local)")

    # Auth: password OR Kerberos
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("-p", "--password", help="Password (not written to disk)")
    auth.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication (no password required; expects valid TGT/ccache in your environment)",
    )

    p.add_argument("--base-out", default="outputs", help="Base output directory (default: outputs)")
    p.add_argument("--run-id", default=None, help="Optional run folder name. Default: timestamp.")
    p.add_argument(
        "--parse-only",
        action="store_true",
        help="Parse an existing raw JSON output file (expects it to exist in the run folder unless --raw-in is used).",
    )
    p.add_argument(
        "--raw-in",
        default=None,
        help="Override raw input file to parse (path). Parsed output still written into this run folder.",
    )
    return p


def compute_paths(domain: str, base_out: Path, run_id: str) -> RunPaths:
    domain_stem = sanitize_domain_for_filename(domain)
    run_dir = base_out / domain_stem / run_id

    raw_out = run_dir / f"{domain_stem}_certificates.txt"
    json_out = run_dir / f"{domain_stem}_certipy"
    parsed_out = run_dir / f"{domain_stem}_certificates_parsed.txt"
    meta_out = run_dir / "run_meta.json"

    return RunPaths(run_dir=run_dir, raw_out=raw_out, json_out=json_out, parsed_out=parsed_out, meta_out=meta_out)


def write_meta(args: Args) -> None:
    # Never write passwords to disk.
    meta = {
        "username": args.username,
        "domain": args.domain,
        "dc_ip": args.dc_ip,
        "auth": "kerberos" if args.kerberos else "password",
        "run_id": args.run_id,
        "run_dir": str(args.paths.run_dir),
        "raw_out": str(args.paths.raw_out),
        "json_out": str(certipy_json_file(args.paths)),
        "parsed_out": str(args.paths.parsed_out),
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    args.paths.meta_out.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


# -------------------------
# Certipy JSON parsing
# -------------------------

def certipy_json_file(paths: RunPaths) -> Path:
    return paths.json_out.with_suffix(".json")

def parse_certipy_json_to_cas(raw_text: str, domain: str) -> list[dict[str, Any]]:
    """
    Parse Certipy JSON output into a normalized list of CAs with templates + vulnerabilities.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Input is not valid JSON: {e}") from e

    ca_section = data.get("Certificate Authorities", {}) or {}
    tpl_section = data.get("Certificate Templates", {}) or {}

    # CA Name -> CA dict
    ca_by_name: dict[str, dict[str, Any]] = {}
    for _, ca in ca_section.items():
        ca_name = (ca.get("CA Name") or "").strip()
        if ca_name:
            ca_by_name[ca_name] = ca

    # CA Name -> list of {template_name, vulnerabilities}
    templates_by_ca: dict[str, list[dict[str, Any]]] = {name: [] for name in ca_by_name.keys()}

    for _, tpl in tpl_section.items():
        tpl_name = (tpl.get("Template Name") or tpl.get("Display Name") or "").strip()
        if not tpl_name:
            continue

        vulns_obj = tpl.get("[!] Vulnerabilities") or {}
        if isinstance(vulns_obj, dict):
            vulns = sorted({str(k).strip().upper() for k in vulns_obj.keys() if str(k).strip()})
        else:
            vulns = []

        ca_list = tpl.get("Certificate Authorities") or []
        if isinstance(ca_list, str):
            ca_list = [ca_list]

        for ca_name in ca_list:
            ca_name = str(ca_name).strip()
            if not ca_name:
                continue
            templates_by_ca.setdefault(ca_name, []).append(
                {"template_name": tpl_name, "vulnerabilities": vulns}
            )

    domain_upn = f"Administrator@{domain}"

    normalized: list[dict[str, Any]] = []
    for ca_name in sorted(ca_by_name.keys(), key=str.lower):
        ca = ca_by_name[ca_name]
        dns_name = (ca.get("DNS Name") or "").strip()

        normalized.append(
            {
                "ca_name": ca_name,
                "dns_name": dns_name,
                "certificate_authorities": ca_name,
                "upn": domain_upn,
                "config": f"{dns_name}\\{ca_name}" if dns_name else f"\\{ca_name}",
                "templates": sorted(
                    templates_by_ca.get(ca_name, []),
                    key=lambda t: (t.get("template_name", "").lower()),
                ),
            }
        )

    return normalized


def write_ca_template_report(cas: list[dict[str, Any]], out_path: Path) -> None:
    """
    Writes CA + template findings in single-line key/value format.
    """
    lines: list[str] = []

    for ca in cas:
        lines.append(f"DNS Name (target) - {ca.get('dns_name', '') or ''}")
        lines.append(f"Certificate Authorities - {ca.get('certificate_authorities', '') or ''}")
        lines.append(f"UPN - {ca.get('upn', '') or ''}")
        lines.append(f"Config - {ca.get('config', '') or ''}")

        lines.append("Template Name")

        templates = ca.get("templates", []) or []
        for t in templates:
            tname = (t.get("template_name") or "").strip()
            if not tname:
                continue

            lines.append(f"  - {tname}")

            vulns = t.get("vulnerabilities") or []
            vulns = [str(v).strip().upper() for v in vulns if str(v).strip()]
            vulns = sorted(set(vulns), key=lambda s: (len(s), s))

            if vulns:
                for v in vulns:
                    lines.append(f"      - {v}")
            else:
                lines.append("      - None")

        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def run_parse(raw_path: Path, parsed_out: Path, domain: str) -> int:
    if not raw_path.exists():
        print(f"[!] Raw input file does not exist: {raw_path}", file=sys.stderr)
        return 2

    raw_text = raw_path.read_text(encoding="utf-8", errors="replace")

    try:
        cas = parse_certipy_json_to_cas(raw_text, domain=domain)
    except ValueError as e:
        print(f"[!] Failed to parse JSON: {e}", file=sys.stderr)
        return 3

    write_ca_template_report(cas, parsed_out)

    template_count = sum(len(ca.get("templates", []) or []) for ca in cas)
    print(f"[+] Parsed {len(cas)} CA(s) and {template_count} template(s)")
    print(f"[+] Wrote parsed output: {parsed_out}")
    return 0


def main(argv: list[str]) -> int:
    ns = build_parser().parse_args(argv)
    
    ccache = os.environ.get("KRB5CCNAME")
    if ccache:
        os.environ["KRB5CCNAME"] = str(Path(ccache).expanduser().resolve())

    base_out = Path(ns.base_out).expanduser().resolve()
    run_id = ns.run_id or default_run_id()

    paths = compute_paths(ns.domain, base_out, run_id)
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    args = Args(
        username=ns.username,
        password=ns.password,     # None if --kerberos
        kerberos=bool(ns.kerberos),
        domain=ns.domain,
        dc_ip=ns.dc_ip,
        target=ns.target,
        base_out=base_out,
        run_id=run_id,
        paths=paths,
    )

    write_meta(args)

    print("[+] Run folder created:")
    print(f"    {args.paths.run_dir}")
    print("[+] Planned outputs:")
    print(f"    raw   : {args.paths.raw_out.name}")
    print(f"    json  : {certipy_json_file(args.paths).name}")
    print(f"    parsed: {args.paths.parsed_out.name}")
    print(f"    meta  : {args.paths.meta_out.name}")

    if ns.raw_in:
        raw_in = Path(ns.raw_in).expanduser().resolve()
        return run_parse(raw_in, args.paths.parsed_out, domain=args.domain)

    if ns.parse_only:
        return run_parse(certipy_json_file(args.paths), args.paths.parsed_out, domain=args.domain)

    # -------------------------------------------------
    # Certipy execution block (find only, auth via if/else)
    # -------------------------------------------------
    
    effective_target = args.target or f"dc.{args.domain}"
    domain_stem = sanitize_domain_for_filename(args.domain)
    output_prefix = f"{domain_stem}_certipy"
    expected_json = args.paths.run_dir / f"{output_prefix}_Certipy.json"

    cmd: list[str] = [
        "certipy-ad",
        "find",
        "-dc-ip", args.dc_ip,
        "-vulnerable",
        "-u", f"{args.username}@{args.domain}",
        "-json",
        "-output", output_prefix, # uses domain name for parsed output
        "-stdout",
    ]

    if args.password:
        # password-authenticated run
        pw = args.password.strip()
        if not pw:
            print("[!] Empty password provided.", file=sys.stderr)
            return 6
        cmd.extend([
            "-p",
            pw,
        ])

    elif args.kerberos:
        # kerberos-authenticated run
        cmd.extend([
            "-k",
            "-no-pass",
            "-target", effective_target,
        ])

    else:
        # argparse should prevent this
        raise RuntimeError("No authentication method selected")
    
    print(" ".join(cmd))

    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=False,
        cwd=str(args.paths.run_dir),
    )

    # Always write stdout so we can parse or debug
    args.paths.raw_out.write_text(proc.stdout or "", encoding="utf-8")

    if proc.stderr:
        (args.paths.run_dir / "certipy_stderr.txt").write_text(
            proc.stderr, encoding="utf-8"
        )

    if proc.returncode != 0:
        print(f"[!] certipy exited non-zero: {proc.returncode}", file=sys.stderr)
        return 4

    print(f"[+] Wrote raw output: {args.paths.raw_out}")

    #json_path = args.paths.json_out.with_suffix(".json")

    if expected_json.exists() and expected_json.stat().st_size > 0:
        print(f"[+] Found Certipy JSON output: {expected_json}")
        return run_parse(expected_json, args.paths.parsed_out, domain=args.domain)

    print("[!] Certipy JSON file missing or empty. Falling back to stdout parse.", file=sys.stderr)
    return run_parse(args.paths.raw_out, args.paths.parsed_out, domain=args.domain)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
