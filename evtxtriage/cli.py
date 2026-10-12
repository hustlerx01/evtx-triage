"""evtx-triage: run rules over EVTX files, write timeline CSV + findings.md, and score
against the technique implied by each public sample's file name (EXPECT table)."""
import argparse, collections, csv, json
from pathlib import Path
from .parse import read_evtx
from .rules import run

EXPECT = {  # sample file -> technique the dataset author says it contains
    "CA_4624_4625_LogonType2_LogonProc_chrome.evtx": None,  # benign-ish logon artefact, no detection expected
    "kerberos_pwd_spray_4771.evtx": "T1110.003",
    "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx": "T1003.001",
    "Powershell_4104_MiniDumpWriteDump_Lsass.evtx": "T1059.001",
    "DE_1102_security_log_cleared.evtx": "T1070.001",
    "DE_Fake_ComputerAccount_4720.evtx": "T1136.002",
    "DE_renamed_psexec_service_sysmon_17_18.evtx": "T1569.002",
    "LM_WMI_4624_4688_TargetHost.evtx": "T1047",
    "LM_renamed_psexecsvc_5145.evtx": "T1569.002",
    "persist_firefox_comhijack_sysmon_11_13_7_1.evtx": "T1546.015",
    "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx": "T1218",
}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("evtx", nargs="+"); ap.add_argument("-o", "--out", default="results")
    a = ap.parse_args(argv); out = Path(a.out); out.mkdir(exist_ok=True)
    rows, md, score = [], ["# EVTX triage findings", ""], []
    for p in a.evtx:
        name = Path(p).name
        evs, errs = read_evtx(p)
        fs = run(evs)
        ids = collections.Counter(e["EventID"] for e in evs)
        md += [f"## {name}", f"records={len(evs)} parse_errors={errs} event_ids={dict(ids.most_common(6))}", ""]
        md += [f"- **[{x['severity']}] {x['rule']}** ({x['mitre']}) {x['time']} - {x['summary']}" for x in fs] or ["- no findings"]
        md.append("")
        for x in fs: rows.append({"file": name, **x})
        exp = EXPECT.get(name, "unknown")
        got = sorted({x["mitre"] for x in fs})
        hit = (exp is None and not fs) or (exp in got)
        score.append({"file": name, "expected": exp, "got": got, "hit": hit, "records": len(evs), "findings": len(fs)})
        print(f"{name:62s} recs={len(evs):4d} findings={len(fs):3d} expected={str(exp):10s} got={got} {'HIT' if hit else 'MISS'}")
    with open(out / "timeline.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["time", "file", "computer", "severity", "rule", "mitre", "summary"]); w.writeheader()
        for r in sorted(rows, key=lambda r: r["time"] or ""): w.writerow({k: r[k] for k in w.fieldnames})
    (out / "findings.md").write_text("\n".join(md))
    json.dump(score, open(out / "score.json", "w"), indent=2)
    print(f"sample-level hit rate: {sum(s['hit'] for s in score)}/{len(score)}")


if __name__ == "__main__":
    main()
