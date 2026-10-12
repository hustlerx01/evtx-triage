"""EVTX -> flat dicts. Works on raw EVTX (python-evtx) or on exported XML strings (tests)."""
import re
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def flatten(xml):
    root = ET.fromstring(xml)
    sys_ = root.find(f"{NS}System")
    ev = {"EventID": int(sys_.findtext(f"{NS}EventID")), "Channel": sys_.findtext(f"{NS}Channel"),
          "Computer": sys_.findtext(f"{NS}Computer"),
          "TimeCreated": (sys_.find(f"{NS}TimeCreated").get("SystemTime") if sys_.find(f"{NS}TimeCreated") is not None else None)}
    for d in root.iter(f"{NS}Data"):
        if d.get("Name"):
            ev[d.get("Name")] = (d.text or "").strip()
    return ev


def read_evtx(path):
    import Evtx.Evtx as evtx
    out, errors = [], 0
    with evtx.Evtx(str(path)) as log:
        for r in log.records():
            try:
                out.append(flatten(r.xml()))
            except Exception:
                errors += 1
    return out, errors
