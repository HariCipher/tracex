"""
Converts each Finding into a numeric confidence score (0-100), so findings
can be ranked instead of just labeled high/medium/low.

Score = base score for the rule type + adjustments based on signal strength.
"""

from detections.rules import Finding, KNOWN_SERVICE_ACCOUNTS


# Base score per rule - reflects how strong a signal each rule type is.
# Privilege escalation sequence is highest because it's a correlated
# multi-step finding (logon + suspicious process from same user) - that
# combination is much less likely to be a false positive than either
# event alone. Suspicious process is lowest because it's single-event,
# no command-line visibility (documented limitation), highest false
# positive rate of the three.
RULE_BASE_SCORE = {
    "brute_force_logon": 60,
    "suspicious_process_execution": 30,
    "privilege_escalation_sequence": 80,
    "explicit_credential_use": 55,
    "account_modification": 50,
}


def score_finding(finding: Finding) -> int:
    """
    Returns a 0-100 confidence score for a single Finding.
    """
    score = RULE_BASE_SCORE.get(finding.rule_name, 20)  # unknown rule = low default

    # Bump score if the finding's own severity label already indicates an
    # escalated/confirmed case (e.g. brute force followed by a successful
    # logon, not just failures).
    if finding.severity == "high":
        score += 10

    # More events involved in one finding can mean a stronger/more
    # sustained pattern, not just a one-off.
    if len(finding.event_ids_involved) >= 5:
        score += 5

    # Known service accounts (Splunk forwarder, TEST$, etc.) are far more
    # likely to be legitimate automation than a human account doing the
    # same thing. privilege_escalation_sequence already excludes them
    # entirely, but suspicious_process_execution doesn't filter on user -
    # down-weight here instead of dropping the finding, since it's still
    # worth visibility, just lower confidence.
    if any(acct in finding.description for acct in KNOWN_SERVICE_ACCOUNTS):
        score -= 15

    # Clamp to 0-100 - the service account penalty could otherwise push
    # a low base score negative, which doesn't make sense for a confidence score.
    return max(0, min(score, 100))


def score_all(findings: list[Finding]) -> list[tuple[Finding, int]]:
    """
    Returns (Finding, score) pairs, sorted highest score first -
    this is what report.py will iterate over to show ranked findings.
    """
    scored = [(f, score_finding(f)) for f in findings]
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored


if __name__ == "__main__":
    # Quick smoke test with fake findings, including a service account case
    test_findings = [
        Finding("brute_force_logon", ["1", "2"], "test", "high"),
        Finding("suspicious_process_execution", ["3"], "test by hari9", "low"),
        Finding("suspicious_process_execution", ["4"], "test by SplunkForwarder", "low"),
        Finding("privilege_escalation_sequence", ["5", "6"], "test", "high"),
        Finding("explicit_credential_use", ["7"], "test", "high"),
        Finding("account_modification", ["8"], "test", "high"),
    ]
    for f, s in score_all(test_findings):
        print(f"{f.rule_name}: {s}  ({f.description})")