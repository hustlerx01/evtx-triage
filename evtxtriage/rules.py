"""Triage rules for Security, Sysmon and PowerShell channels. Each returns findings
{rule, mitre, severity, time, summary}."""
import re
from collections import defaultdict

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS_KEYWORDS = re.compile(r"(MiniDumpWriteDump|Invoke-Mimikatz|sekurlsa|DumpCreds|Invoke-Shellcode|VirtualAlloc|FromBase64String|Net\.WebClient|DownloadString|AmsiUtils)", re.I)
LSASS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x40"}


def hexnorm(v):
    """'0x00001010' and '0x1010' must compare equal (bug found on real EVTX)."""
    try:
        return hex(int(v, 16))
    except (TypeError, ValueError):
        return (v or "").lower()


def link_parents(evs):
    """Old 4688 events have no ParentProcessName: rebuild it from ProcessId -> NewProcessId."""
    names = {}
    for e in evs:
        if e["EventID"] == 4688 and e.get("NewProcessId"):
            names[(e.get("Computer"), hexnorm(e["NewProcessId"]))] = e.get("NewProcessName", "")
    for e in evs:
        if e["EventID"] == 4688 and not e.get("ParentProcessName") and e.get("ProcessId"):
            e["ParentProcessName"] = names.get((e.get("Computer"), hexnorm(e["ProcessId"])), "")
    return evs


WMI_BENIGN_CHILD = ("\\werfault.exe", "\\wmiprvse.exe", "\\wmiapsrv.exe")


def f(rule, mitre, sev, ev, summary):
    return {"rule": rule, "mitre": mitre, "severity": sev, "time": ev.get("TimeCreated") or ev.get("UtcTime"), "computer": ev.get("Computer"), "summary": summary}


def r_failed_logons(evs):
    by = defaultdict(list)
    for e in evs:
        if e["EventID"] == 4625: by[e.get("IpAddress") or e.get("WorkstationName") or "-"].append(e)
        # 4771 0x18 = bad password (pre-auth); 4768 0x6 = unknown principal (user enumeration/spray)
        if (e["EventID"] == 4771 and hexnorm(e.get("Status")) == "0x18") or (e["EventID"] == 4768 and hexnorm(e.get("Status")) == "0x6"):
            by["kerb:" + (e.get("IpAddress") or "-").replace("::ffff:", "")].append(e)
    out = []
    for src, g in by.items():
        users = {e.get("TargetUserName") for e in g}
        if len(users) >= 5:
            out.append(f("password_spray", "T1110.003", "high", g[0], f"{len(g)} failures across {len(users)} accounts from {src}"))
        elif len(g) >= 10:
            out.append(f("brute_force", "T1110.001", "medium", g[0], f"{len(g)} failures for {users} from {src}"))
    return out


def r_single(evs):
    out = []
    for e in evs:
        eid, ch = e["EventID"], e.get("Channel", "")
        if eid == 1102 and ch == "Security":
            out.append(f("security_log_cleared", "T1070.001", "high", e, f"Security log cleared by {e.get('SubjectUserName', '?')}"))
        if eid == 4720 and e.get("TargetUserName", "").endswith("$"):
            out.append(f("computer_account_via_4720", "T1136.002", "medium", e, f"{e.get('SubjectUserName')} created account {e.get('TargetUserName')} (machine-style name via user-creation API)"))
        elif eid == 4720:
            out.append(f("user_created", "T1136.001", "low", e, f"user {e.get('TargetUserName')} created by {e.get('SubjectUserName')}"))
        if eid == 5145 and re.search(r"-(stdin|stdout|stderr)$|PSEXESVC|RemCom", e.get("RelativeTargetName", ""), re.I):
            out.append(f("psexec_like_pipe_over_smb", "T1569.002", "high", e, f"{e.get('IpAddress')} opened IPC$ pipe '{e.get('RelativeTargetName')}' as {e.get('SubjectUserName')}"))
        if ch == SYSMON and eid in (17, 18) and re.search(r"-(stdin|stdout|stderr)$|\\PSEXESVC", e.get("PipeName", ""), re.I):
            out.append(f("psexec_like_named_pipe", "T1569.002", "high", e, f"pipe {e.get('PipeName')} by {e.get('Image')}"))
        if ch == SYSMON and eid == 10 and e.get("TargetImage", "").lower().endswith("\\lsass.exe") and hexnorm(e.get("GrantedAccess")) in {hexnorm(m) for m in LSASS_MASKS}:
            out.append(f("lsass_access", "T1003.001", "critical", e, f"{e.get('SourceImage')} opened lsass with {e.get('GrantedAccess')}"))
        if eid == 4104 and PS_KEYWORDS.search(e.get("ScriptBlockText", "")):
            kw = sorted({m.group(0) for m in PS_KEYWORDS.finditer(e.get("ScriptBlockText", ""))})
            out.append(f("suspicious_scriptblock", "T1059.001", "high", e, f"PowerShell script block contains {kw}"))
        if ch == SYSMON and eid == 13 and re.search(r"(\\Software\\Classes|_CLASSES)\\CLSID\\.*\\(InprocServer32|LocalServer32)", e.get("TargetObject", ""), re.I) and "HKU" in e.get("TargetObject", "").upper():
            out.append(f("com_hijack_hkcu", "T1546.015", "high", e, f"{e.get('Image')} set {e.get('TargetObject')} = {e.get('Details')}"))
        img, cmd, parent = e.get("Image", "") or e.get("NewProcessName", ""), e.get("CommandLine", ""), e.get("ParentImage", "") or e.get("ParentProcessName", "")
        if (ch == SYSMON and eid == 1) or eid == 4688:
            il, cl, pl = img.lower(), cmd.lower(), parent.lower()
            if pl.endswith("\\wmiprvse.exe") and il.endswith(("\\cmd.exe", "\\powershell.exe")):
                out.append(f("wmi_spawned_shell", "T1047", "high", e, f"WmiPrvSE spawned {img}: {cmd[:120]}"))
            elif pl.endswith("\\wmiprvse.exe") and not il.endswith(WMI_BENIGN_CHILD):
                out.append(f("wmi_child_process", "T1047", "medium", e, f"WmiPrvSE spawned {img} (remote WMI exec?)"))
            if il.endswith("\\mshta.exe") or (il.endswith("\\rundll32.exe") and re.search(r"javascript:|mshtml|url\.dll|shdocvw|zipfldr", cl)):
                out.append(f("lolbin_proxy_exec", "T1218", "high", e, f"{img}: {cmd[:120]}"))
            if il.endswith("\\schtasks.exe") and "/create" in cl:
                out.append(f("scheduled_task_created", "T1053.005", "medium", e, f"{cmd[:140]}"))
    return out


SYSTEM_ACCTS = {"system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0"}


def r_logon_after_failures(evs, threshold=5):
    """4624 success for an account that had >= threshold 4625 failures before it (from any source)."""
    fails, out = defaultdict(int), []
    for e in sorted(evs, key=lambda x: x.get("TimeCreated") or ""):
        user = (e.get("TargetUserName") or "").lower()
        if e["EventID"] == 4625:
            fails[user] += 1
        elif e["EventID"] == 4624 and fails.get(user, 0) >= threshold:
            out.append(f("logon_after_failures", "T1110", "high", e, f"{e.get('TargetUserName')} logged on (type {e.get('LogonType', '?')}) from {e.get('IpAddress', '-')} after {fails[user]} failures"))
            fails[user] = 0
    return out


def r_special_privileges(evs):
    """4672: special privileges assigned to a new logon; ignore machine and built-in service accounts."""
    out = []
    for e in evs:
        u = e.get("SubjectUserName") or ""
        if e["EventID"] == 4672 and not u.endswith("$") and u.lower() not in SYSTEM_ACCTS:
            privs = " ".join((e.get("PrivilegeList") or "").split())
            sev = "medium" if "SeDebugPrivilege" in privs else "low"
            out.append(f("special_privileges_logon", "T1078", sev, e, f"{u} got special privileges at logon: {privs[:120]}"))
    return out


RULES = [r_failed_logons, r_single, r_logon_after_failures, r_special_privileges]


def run(evs):
    evs = link_parents(evs)
    out = []
    for r in RULES:
        out += r(evs)
    return sorted(out, key=lambda x: x["time"] or "")
