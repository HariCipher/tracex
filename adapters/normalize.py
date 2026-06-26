"""
normalize.py

Maps the inconsistent field names Windows uses across different EventIDs
into one consistent schema, so detection logic doesn't need to special-case
every EventID's naming quirks.

Example of the problem this solves:
  - EventID 4720 (user created) uses "TargetUserName" for the affected account
  - EventID 4625 (failed logon) uses "TargetUserName" too, but the source IP
    field is "IpAddress"
  - EventID 4732 (group membership change) uses "MemberName" for who got added

This is the same field-mismatch problem already hit in Splunk lab work
(ScriptBlockText vs Message, src_ip vs Source_Network_Address) - same fix,
different platform.

IMPORTANT: this file only renames/restructures fields. It makes zero
judgment calls about what's suspicious. That logic belongs in detections/rules.py.
"""

from dataclasses import dataclass, field
from typing import Optional
from adapters.evtx_adapter import RawEvent


@dataclass
class NormalizedEvent:
    """Consistent schema, regardless of which EventID produced it."""
    event_id: str
    timestamp: str
    computer: str
    channel: str
    record_id: str

    # Normalized identity fields - None if not applicable to this EventID
    target_user: Optional[str] = None      # account being acted upon
    subject_user: Optional[str] = None     # account that performed the action
    source_ip: Optional[str] = None
    logon_type: Optional[str] = None
    group_name: Optional[str] = None       # for group membership events
    service_name: Optional[str] = None     # for service installation events
    process_name: Optional[str] = None     # for process creation events (4688)
    command_line: Optional[str] = None     # for process creation events (4688)
    parent_process: Optional[str] = None   # for process creation events (4688)
    privilege_list: Optional[str] = None   # for special privilege assignment (4672)

    # Full original field dict kept for anything not yet normalized -
    # detection rules can fall back to this if a field isn't mapped above
    raw_fields: dict = field(default_factory=dict)


# Field name lookup table, per EventID.
# Add a row here whenever you write a detection rule for a new EventID
# and discover its field names don't match what's already mapped.
FIELD_MAP = {
    "4720": {  # User account created
        "target_user": "TargetUserName",
        "subject_user": "SubjectUserName",
    },
    "4732": {  # Member added to a security-enabled local group
        "target_user": "MemberName",
        "subject_user": "SubjectUserName",
        "group_name": "TargetUserName",  # group name lands here for 4732
    },
    "4625": {  # Failed logon
        "target_user": "TargetUserName",
        "source_ip": "IpAddress",
        "logon_type": "LogonType",
    },
    "4624": {  # Successful logon
        "target_user": "TargetUserName",
        "source_ip": "IpAddress",
        "logon_type": "LogonType",
    },
    "7045": {  # Service installed
        "subject_user": "AccountName",
        "service_name": "ServiceName",
    },
    "4688": {  # Process created
        "subject_user": "SubjectUserName",
        "process_name": "NewProcessName",
        "command_line": "CommandLine",
        "parent_process": "ParentProcessName",
    },
    "4672": {  # Special privileges assigned to new logon
        "subject_user": "SubjectUserName",
        "privilege_list": "PrivilegeList",
    },
    "4798": {  # A user's local group membership was enumerated
        "subject_user": "SubjectUserName",
        "target_user": "TargetUserName",
    },
    "4799": {  # A security-enabled local group membership was enumerated
        "subject_user": "SubjectUserName",
        "group_name": "TargetUserName",
    },
    "4648": {  # Explicit credential logon
    "subject_user": "SubjectUserName",
    "target_user": "TargetUserName",
    "source_ip": "IpAddress",
    "process_name": "ProcessName",
    },
    "4738": {  # User account modified
    "subject_user": "SubjectUserName",
    "target_user": "TargetUserName",
},
}


def normalize_event(raw: RawEvent) -> NormalizedEvent:
    """
    Convert a RawEvent into a NormalizedEvent using FIELD_MAP.
    Unmapped EventIDs still get a NormalizedEvent - just with the
    identity fields left as None and everything available in raw_fields.
    """
    mapping = FIELD_MAP.get(raw.event_id, {})

    def get_mapped(key: str) -> Optional[str]:
        source_field = mapping.get(key)
        if source_field:
            return raw.event_data.get(source_field)
        return None

    return NormalizedEvent(
        event_id=raw.event_id or "",
        timestamp=raw.time_created or "",
        computer=raw.computer or "",
        channel=raw.channel or "",
        record_id=raw.record_id or "",
        target_user=get_mapped("target_user"),
        subject_user=get_mapped("subject_user"),
        source_ip=get_mapped("source_ip"),
        logon_type=get_mapped("logon_type"),
        group_name=get_mapped("group_name"),
        service_name=get_mapped("service_name"),
        process_name=get_mapped("process_name"),
        command_line=get_mapped("command_line"),
        parent_process=get_mapped("parent_process"),
        privilege_list=get_mapped("privilege_list"),
        raw_fields=raw.event_data,
    )


def normalize_all(raw_events: list[RawEvent]) -> list[NormalizedEvent]:
    return [normalize_event(e) for e in raw_events]
