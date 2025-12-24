#!/usr/bin/env python3
import argparse
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

"""

In order to crack passwords using this script, you need the --crack command
and a supplied wordlist

The file example_dump.txt is an example secretsdump that came from GOAD

After running "secretsdump.py <user>:<pass>@<IP> -just-dc-ntlm | tee dump.txt" you
have a dump file, and can run this script to get the following files:

hashcat_show.txt - The output of "hashcat --show"
nt_hashes.txt    - List of all NT hashes dumped
users.txt        - Wordlist of all usernamed dumped
passwords.txt    - Wordlist of all cracked hashes
user_hashes.txt  - List of all users and their associated NTLM hashes
user_pass.txt    - List of all users and their cracked passwords (only cracked users placed here)


EXAMPLE:
python3 parse_secretsdump.py -i dump.txt --crack --wordlist rockyou.txt

"""

# Matches BOTH:
#  - DCSync:   user:RID:LM:NT:::
#  - Local SAM: MACHINE\user:RID:LM:NT:::
DUMP_LINE_RE = re.compile(
    r"""
    ^(?P<user>[^:\r\n]+)
    :(?P<rid>\d+)
    :(?P<lm>[0-9a-fA-F]{32})
    :(?P<nt>[0-9a-fA-F]{32})
    :{3}
    """,
    re.VERBOSE,
)

def normalize_user(raw_user: str, keep_domain_prefix: bool) -> str:
    """
    raw_user might be:
      - Administrator
      - DOMAIN\\Administrator
      - DC01\\Administrator
    """
    if keep_domain_prefix:
        return raw_user
    # Drop prefix up to last backslash
    if "\\" in raw_user:
        return raw_user.split("\\")[-1]
    return raw_user

def parse_dump(text: str, include_machine: bool, keep_domain_prefix: bool) -> List[Tuple[str, str, str]]:
    """
    Returns list of (user, lmhash, nthash) in order encountered, de-duped.
    """
    out: List[Tuple[str, str, str]] = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()
        m = DUMP_LINE_RE.match(line)
        if not m:
            continue

        user_raw = m.group("user")
        user = normalize_user(user_raw, keep_domain_prefix=keep_domain_prefix)

        # Skip Guest account (usually empty password)
        if user.lower() == "guest":
            continue

        lm = m.group("lm").lower()
        nt = m.group("nt").lower()

        # Skip machine accounts like DC01$ (common in domain dumps)
        if (not include_machine) and user.endswith("$"):
            continue

        key = (user.lower(), lm, nt)
        if key in seen:
            continue
        seen.add(key)

        out.append((user, lm, nt))

    return out

def write_lines(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def which_or_die(binary: str) -> str:
    p = shutil.which(binary)
    if not p:
        raise SystemExit(f"ERROR: '{binary}' not found in PATH. Install it or fix PATH.")
    return p

def run_hashcat_crack(
    hashcat_path: str,
    nt_hashes_file: Path,
    outdir: Path,
    mode: int,
    attack: int,
    wordlist: Optional[Path],
    rules: Optional[Path],
    extra_args: List[str],
    session: str,
) -> Path:
    """
    Runs hashcat and then exports cracked results via --show into a file:
      outdir/hashcat_show.txt  (format: hash:password)
    Returns that file path.
    """
    # Build base crack command
    cmd = [hashcat_path, "-m", str(mode), "-a", str(attack), str(nt_hashes_file)]

    # Common case: straight wordlist attack (-a 0) needs a wordlist
    if attack == 0:
        if not wordlist:
            raise SystemExit("ERROR: attack mode -a 0 requires --wordlist.")
        cmd.append(str(wordlist))

    # Add rules if provided (works with -a 0 typically)
    if rules:
        cmd.extend(["-r", str(rules)])

    # Add a session name so you can resume if you want
    cmd.extend(["--session", session])

    # Add any other user-provided args (e.g., --force, -O, --status, etc.)
    cmd.extend(extra_args)

    # Run cracking
    print("[*] Running hashcat:")
    print("    " + " ".join(cmd))
    res = subprocess.run(cmd, text=True)
    if res.returncode not in (0, 1, 2):  # 0=OK, 1=exhausted, 2=error usually
        print(f"[!] hashcat returned code {res.returncode} (may still have cracked some).")

    # Export cracked results
    show_file = outdir / "hashcat_show.txt"
    show_cmd = [hashcat_path, "-m", str(mode), "--show", str(nt_hashes_file)]
    print("[*] Exporting cracked hashes via hashcat --show:")
    print("    " + " ".join(show_cmd))
    show = subprocess.run(show_cmd, capture_output=True, text=True)

    # hashcat --show prints to stdout in "hash:password" (or similar) format
    show_file.write_text(show.stdout, encoding="utf-8")
    return show_file

def read_hashcat_show(path: Path) -> Dict[str, str]:
    """
    Reads hashcat --show output (hash:password).
    Returns dict {hash_lower: password}.
    """
    mapping: Dict[str, str] = {}
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        h, pw = line.split(":", 1)
        h = h.strip().lower()
        pw = pw.strip()
        if re.fullmatch(r"[0-9a-f]{32}", h):
            mapping[h] = pw
    return mapping

def main():
    ap = argparse.ArgumentParser(
        description="Parse secretsdump output (DCSync or local SAM) and optionally run hashcat to crack NTLM."
    )
    ap.add_argument("-i", "--input", required=True, help="Path to secretsdump output text file (saved output).")
    ap.add_argument("-o", "--outdir", default="secretsdump", help="Output directory (default: secretsdump)")
    ap.add_argument("--include-machine", action="store_true", help="Include machine accounts ending with '$'")
    ap.add_argument("--keep-domain-prefix", action="store_true",
                    help=r"Keep DOMAIN\user or MACHINE\user prefix in outputs (default strips prefix).")

    # Hashcat options
    ap.add_argument("--crack", action="store_true", help="Run hashcat automatically.")
    ap.add_argument("--hashcat", default="hashcat", help="Hashcat binary (default: hashcat)")
    ap.add_argument("--mode", type=int, default=1000, help="Hash mode (default: 1000 for NTLM)")
    ap.add_argument("--attack", type=int, default=0, help="Attack mode (default: 0 = straight wordlist)")
    ap.add_argument("--wordlist", help="Wordlist path (required for -a 0)")
    ap.add_argument("--rules", help="Hashcat rules file path (optional)")
    ap.add_argument("--session", default="secretsdump_ntlm", help="Hashcat session name (default: secretsdump_ntlm)")
    ap.add_argument("--hashcat-arg", action="append", default=[],
                    help="Extra hashcat argument (repeatable). Example: --hashcat-arg --force")

    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    dump_text = Path(args.input).read_text(errors="ignore")
    entries = parse_dump(
        dump_text,
        include_machine=args.include_machine,
        keep_domain_prefix=args.keep_domain_prefix
    )

    # Outputs you asked for
    # user_hashes.txt (FULL LM:NT)
    write_lines(outdir / "user_hashes.txt", [f"{u} - {lm}:{nt}" for (u, lm, nt) in entries])

    # users.txt
    write_lines(outdir / "users.txt", [u for (u, _, _) in entries])

    # nt_hashes.txt (hashcat input)
    nt_hashes_file = outdir / "nt_hashes.txt"
    write_lines(nt_hashes_file, [nt for (_, _, nt) in entries])

    # Defaults if we don't crack
    (outdir / "user_pass.txt").write_text("", encoding="utf-8")
    (outdir / "passwords.txt").write_text("", encoding="utf-8")

    if args.crack:
        hashcat_path = which_or_die(args.hashcat)

        wordlist = Path(args.wordlist) if args.wordlist else None
        rules = Path(args.rules) if args.rules else None
        extra_args = args.hashcat_arg or []

        show_file = run_hashcat_crack(
            hashcat_path=hashcat_path,
            nt_hashes_file=nt_hashes_file,
            outdir=outdir,
            mode=args.mode,
            attack=args.attack,
            wordlist=wordlist,
            rules=rules,
            extra_args=extra_args,
            session=args.session,
        )

        cracked_map = read_hashcat_show(show_file)

        user_pass_lines: List[str] = []
        pw_set = set()

        for user, _, nt in entries:
            pw = cracked_map.get(nt)
            if pw is None:
                continue
            user_pass_lines.append(f"{user} - {pw}")
            pw_set.add(pw)

        write_lines(outdir / "user_pass.txt", user_pass_lines)
        write_lines(outdir / "passwords.txt", sorted(pw_set))

    print(f"[*] Done. Outputs in: {outdir.resolve()}")

if __name__ == "__main__":
    main()

