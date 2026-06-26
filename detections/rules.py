"""
rules.py

THIS FILE IS YOURS TO WRITE.

Each rule takes a list of NormalizedEvent objects and returns a list of
Finding objects for whatever it flags as suspicious.

Interface is fixed so it plugs into the rest of the pipeline -
the actual "what's suspicious" logic is 100% your call.
"""

from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict
from adapters.normalize import NormalizedEvent

SUSPICIOUS_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "certutil.exe", "rundll32.exe"]

@dataclass
class Finding:
    rule_name: str
    event_ids_involved: list[str]  
    description: str
    severity: str 


def _parse_time(ts: str) -> datetime:
    """EVTX timestamps look like '2026-05-25 15:30:34.824968+00:00'"""
    return datetime.fromisoformat(ts)


def detect_brute_force(events: list[NormalizedEvent]) -> list[Finding]:
    
    findings = []

    failed_logons = [e for e in events if e.event_id == "4625" and e.source_ip]

    by_ip = defaultdict(list)
    for evt in failed_logons:
        by_ip[evt.source_ip].append(evt)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: _parse_time(e.timestamp))

        cluster = [attempts[0]]
        for evt in attempts[1:]:
            gap = (_parse_time(evt.timestamp) - _parse_time(cluster[-1].timestamp)).total_seconds()
            if gap <= 300:  
                cluster.append(evt)
            else:
                if len(cluster) >= 4:
                    findings.append(_build_brute_force_finding(ip, cluster, events))
                cluster = [evt]

        if len(cluster) >= 4:
            findings.append(_build_brute_force_finding(ip, cluster, events))

    return findings


def _build_brute_force_finding(ip: str, cluster: list[NormalizedEvent], all_events: list[NormalizedEvent]) -> Finding:
    record_ids = [e.record_id for e in cluster]
    start_time = cluster[0].timestamp
    end_time = cluster[-1].timestamp

    last_fail_time = _parse_time(cluster[-1].timestamp)
    followed_by_success = False
    for evt in all_events:
        if evt.event_id == "4624" and evt.source_ip == ip:
            success_time = _parse_time(evt.timestamp)
            delta = (success_time - last_fail_time).total_seconds()
            if 0 <= delta <= 300:
                followed_by_success = True
                break

    severity = "high" if followed_by_success else "medium"
    desc = (
        f"{len(cluster)} failed logon attempts from {ip} between {start_time} and {end_time}."
    )
    if followed_by_success:
        desc += " Followed by a SUCCESSFUL logon from the same IP shortly after - possible successful brute force."

    return Finding(
        rule_name="brute_force_logon",
        event_ids_involved=record_ids,
        description=desc,
        severity=severity,
    )


def detect_suspicious_process(events: list[NormalizedEvent]) -> list[Finding]:
   
    findings = []

    SUSPICIOUS_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "certutil.exe", "rundll32.exe"]
    KNOWN_SERVICE_ACCOUNTS = ["SplunkForwarder", "TEST$"]

    for evt in events:
        if evt.event_id != "4688" or not evt.process_name:
            continue

        proc_lower = evt.process_name.lower()
        match = next((p for p in SUSPICIOUS_PROCESS_NAMES if proc_lower.endswith(p)), None)

        if match:
            findings.append(Finding(
                rule_name="suspicious_process_execution",
                event_ids_involved=[evt.record_id],
                description=(
                    f"Suspicious process executed: {evt.process_name} "
                    f"by {evt.subject_user or 'unknown user'} at {evt.timestamp}."
                ),
                severity="low",  
            ))

    return findings

KNOWN_SERVICE_ACCOUNTS = ["SplunkForwarder", "TEST$"]


def detect_privilege_escalation_sequence(events: list[NormalizedEvent]) -> list[Finding]:
    
    findings = []

    special_privilege_logons = [e for e in events if e.event_id == "4672"]
    suspicious_procs = [
        e for e in events
        if e.event_id == "4688" and e.process_name
        and any(e.process_name.lower().endswith(p) for p in SUSPICIOUS_PROCESS_NAMES)
    ]

    for logon in special_privilege_logons:
        if not logon.subject_user:
            continue
        if logon.subject_user in KNOWN_SERVICE_ACCOUNTS:
            continue

        logon_time = _parse_time(logon.timestamp)

        for proc in suspicious_procs:
            if proc.subject_user != logon.subject_user:
                continue
            proc_time = _parse_time(proc.timestamp)
            time_diff = (proc_time - logon_time).total_seconds()

            if 0 <= time_diff <= 300:
                findings.append(Finding(
                    rule_name="privilege_escalation_sequence",
                    event_ids_involved=[logon.record_id, proc.record_id],
                    description=(
                        f"Privilege escalation sequence: {logon.subject_user} "
                        f"granted special privileges at {logon.timestamp}, then "
                        f"executed {proc.process_name} at {proc.timestamp} "
                        f"({time_diff:.0f}s later)."
                    ),
                    severity="high",
                ))

    return findings

def detect_explicit_credential_use(events: list[NormalizedEvent]) -> list[Finding]:
   
    findings = []

    for evt in events:
        if evt.event_id != "4648":
            continue
        if not evt.subject_user or not evt.target_user:
            continue
        if evt.subject_user in KNOWN_SERVICE_ACCOUNTS:
            continue
        if evt.subject_user == evt.target_user:
            continue
        if evt.source_ip == "127.0.0.1" and evt.subject_user.endswith("$"):
            continue

        findings.append(Finding(
            rule_name="explicit_credential_use",
            event_ids_involved=[evt.record_id],
            description=(
                f"Explicit credential logon: {evt.subject_user} authenticated "
                f"as {evt.target_user} via {evt.process_name or 'unknown process'} "
                f"from {evt.source_ip or 'unknown IP'} at {evt.timestamp}."
            ),
            severity="medium",
        ))

    return findings


def detect_account_modification(events: list[NormalizedEvent]) -> list[Finding]:
   
    findings = []

    for evt in events:
        if evt.event_id != "4738":
            continue
        if not evt.subject_user or not evt.target_user:
            continue
        if evt.subject_user == evt.target_user:
            continue  

        findings.append(Finding(
            rule_name="account_modification",
            event_ids_involved=[evt.record_id],
            description=(
                f"User account modified: {evt.subject_user} modified "
                f"account {evt.target_user} at {evt.timestamp}."
            ),
            severity="medium",
        ))

    return findings
ALL_RULES = [
    detect_brute_force,
    detect_suspicious_process,
    detect_privilege_escalation_sequence,
    detect_explicit_credential_use,
    detect_account_modification,
]

def run_all_rules(events: list[NormalizedEvent]) -> list[Finding]:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(events))
    return findings
