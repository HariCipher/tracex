"""
evtx_adapter.py

Parses raw .evtx files into a list of Event objects.
Pure parsing layer - no detection logic lives here.
"""

from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


@dataclass
class RawEvent:
    """One parsed EVTX record, fields still in their original Windows names."""
    event_id: Optional[str] = None
    time_created: Optional[str] = None
    computer: Optional[str] = None
    channel: Optional[str] = None
    record_id: Optional[str] = None
    event_data: dict = field(default_factory=dict)
    raw_xml: str = ""


def parse_evtx(filepath: str) -> list[RawEvent]:
    """
    Parse an EVTX file and return a list of RawEvent objects.
    Each RawEvent holds the System fields plus a dict of all EventData
    Name/Value pairs exactly as Windows wrote them (no renaming here -
    that happens in normalize.py).
    """
    events = []

    with Evtx(filepath) as log:
        for record in log.records():
            xml_str = record.xml()
            try:
                root = ET.fromstring(xml_str)
            except ET.ParseError:
                # Malformed record - skip rather than crash the whole run
                continue

            evt = RawEvent(raw_xml=xml_str)

            system = root.find('e:System', NS)
            if system is not None:
                eid_elem = system.find('e:EventID', NS)
                if eid_elem is not None:
                    evt.event_id = eid_elem.text

                time_elem = system.find('e:TimeCreated', NS)
                if time_elem is not None:
                    evt.time_created = time_elem.get('SystemTime')

                computer_elem = system.find('e:Computer', NS)
                if computer_elem is not None:
                    evt.computer = computer_elem.text

                channel_elem = system.find('e:Channel', NS)
                if channel_elem is not None:
                    evt.channel = channel_elem.text

                record_id_elem = system.find('e:EventRecordID', NS)
                if record_id_elem is not None:
                    evt.record_id = record_id_elem.text

            event_data = root.find('e:EventData', NS)
            if event_data is not None:
                for data in event_data.findall('e:Data', NS):
                    name = data.get('Name')
                    if name:
                        evt.event_data[name] = data.text

            events.append(evt)

    return events


if __name__ == "__main__":
    # Quick smoke test
    import sys
    if len(sys.argv) < 2:
        print("Usage: python evtx_adapter.py <path-to-evtx>")
        sys.exit(1)

    parsed = parse_evtx(sys.argv[1])
    print(f"Parsed {len(parsed)} events")
    if parsed:
        sample = parsed[0]
        print(f"Sample - EventID: {sample.event_id}, Time: {sample.time_created}")
        print(f"EventData keys: {list(sample.event_data.keys())}")
