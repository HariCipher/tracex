"""
main.py — TRACEX CLI entry point
"""

import sys
import os
import time
from colorama import init, Fore, Style
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
init(autoreset=True)

from adapters.evtx_adapter import parse_evtx
from adapters.normalize import normalize_all
from detections.rules import run_all_rules
from scoring import score_all
from db import init_db, save_run, DB_PATH
from dashboard import generate_dashboard
from mitre_map import MITRE_MAP

VERSION = "1.0.0"

BANNER = f"""
{Fore.RED}
████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝
   ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝ 
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗ 
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}  Windows Event Log Analyzer — Detection & MITRE ATT&CK Mapping{Style.RESET_ALL}
{Fore.RED}  ─────────────────────────────────────────────────────────────{Style.RESET_ALL}
"""


def print_help():
    print(BANNER)
    print(f"  {Fore.RED}USAGE{Style.RESET_ALL}")
    print(f"    tracex <path-to-evtx>         Analyze an EVTX file")
    print(f"    tracex --help                 Show this menu")
    print(f"    tracex --version              Show version")
    print(f"    tracex --clear-db             Wipe findings database\n")
    print(f"  {Fore.RED}DETECTION RULES{Style.RESET_ALL}")
    print(f"    brute_force_logon             4625 cluster + 4624 success follow")
    print(f"    suspicious_process_execution  LOLBin process names via 4688")
    print(f"    privilege_escalation_sequence 4672 → suspicious process same user")
    print(f"    explicit_credential_use       4648 alternate credential logon")
    print(f"    account_modification          4738 account modified by another user\n")
    print(f"  {Fore.RED}OUTPUT{Style.RESET_ALL}")
    print(f"    dashboard.html     Interactive HTML dashboard, opens in browser")
    print(f"    tracex.db          SQLite findings database, persists across runs\n")
    print(f"  {Fore.RED}EXAMPLE{Style.RESET_ALL}")
    print(f"    tracex C:\\path\\to\\Security.evtx")
    print(f"    tracex /home/kali/Security.evtx\n")
    print(f"  {Fore.RED}──────────────────────────────────────────────────────{Style.RESET_ALL}\n")


def print_version():
    print(BANNER)
    print(f"  {Fore.WHITE}TRACEX v{VERSION}{Style.RESET_ALL}")
    print(f"  {Fore.RED}github.com/HariCipher/tracex{Style.RESET_ALL}\n")

def clear_db():
    print(BANNER)
    if not os.path.isfile(DB_PATH):
        print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL}  No database found — nothing to clear.\n")
        return
    confirm = input(f"  {Fore.RED}This will delete all findings history. Confirm? (yes/no): {Style.RESET_ALL}")
    if confirm.strip().lower() == "yes":
        os.remove(DB_PATH)
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL}  Database cleared.\n")
    else:
        print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL}  Cancelled.\n")


def print_step(icon: str, msg: str):
    print(f"  {Fore.CYAN}{icon}{Style.RESET_ALL}  {msg}")


def print_success(msg: str):
    print(f"  {Fore.GREEN}✓{Style.RESET_ALL}  {msg}")


def print_finding_summary(scored):
    high   = sum(1 for f, s in scored if f.severity == "high")
    medium = sum(1 for f, s in scored if f.severity == "medium")
    low    = sum(1 for f, s in scored if f.severity == "low")

    print(f"\n  {Fore.WHITE}┌─ Findings Summary {'─'*36}┐{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}│{Style.RESET_ALL}  Total   : {Fore.WHITE}{len(scored)}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}│{Style.RESET_ALL}  {Fore.RED}High    : {high}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}│{Style.RESET_ALL}  {Fore.YELLOW}Medium  : {medium}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}│{Style.RESET_ALL}  {Fore.WHITE}Low     : {low}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}└{'─'*55}┘{Style.RESET_ALL}\n")

    if scored:
        print(f"  {Fore.RED}Top findings:{Style.RESET_ALL}")
        for finding, score in scored[:3]:
            sev_color = Fore.RED if finding.severity == "high" else Fore.YELLOW if finding.severity == "medium" else Fore.WHITE
            desc = finding.description[:72] + "..." if len(finding.description) > 72 else finding.description
            print(f"  {sev_color}[{score:>3}]{Style.RESET_ALL}  {finding.rule_name}  —  {desc}")
        print()


def open_browser(path: str):
    abs_path = os.path.abspath(path)
    if sys.platform == "win32":
        os.startfile(abs_path)
    else:
        import subprocess
        subprocess.Popen(["xdg-open", abs_path])


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "--help"

    if arg in ("--help", "-h"):
        print_help()
        return

    if arg in ("--version", "-v"):
        print_version()
        return

    if arg == "--clear-db":
        clear_db()
        return

    filepath = arg
    print(BANNER)

    if not os.path.isfile(filepath):
        print(f"  {Fore.RED}✗{Style.RESET_ALL}  File not found: {filepath}\n")
        sys.exit(1)

    print_step("→", f"Source: {filepath}\n")

    print_step("⧗", "Parsing EVTX file...")
    t0 = time.time()
    raw = parse_evtx(filepath)
    print_success(f"Parsed {len(raw):,} events  ({time.time()-t0:.1f}s)")

    print_step("⧗", "Normalizing events...")
    normalized = normalize_all(raw)
    print_success(f"Normalized {len(normalized):,} events")

    print_step("⧗", "Running detection rules...")
    findings = run_all_rules(normalized)
    print_success(f"Detection complete — {len(findings)} raw findings")

    print_step("⧗", "Scoring and ranking findings...")
    scored = score_all(findings)
    print_success("Scoring complete")

    print_finding_summary(scored)

    print_step("⧗", "Saving to database...")
    init_db()
    run_id = save_run(filepath, len(raw), scored, MITRE_MAP)
    print_success(f"Saved to database (run_id: {run_id})")

    print_step("⧗", "Generating dashboard...")
    path = generate_dashboard()
    print_success(f"Dashboard: {os.path.abspath(path)}")

    open_browser(path)
    print(f"\n  {Fore.RED}Opening dashboard in browser...{Style.RESET_ALL}")
    print(f"\n  {Fore.RED}{'─'*55}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()