from evtxtriage.parse import flatten
from evtxtriage.rules import run

T = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID>
<TimeCreated SystemTime="2026-10-11 10:00:00"/><Channel>{ch}</Channel><Computer>WS1</Computer></System><EventData>{data}</EventData></Event>'''


def ev(eid, ch="Security", **data):
    return flatten(T.format(eid=eid, ch=ch, data="".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())))


SYS = "Microsoft-Windows-Sysmon/Operational"


def rules_of(evs):
    return {x["rule"] for x in run(evs)}


def test_flatten():
    e = ev(4625, IpAddress="192.0.2.5", TargetUserName="bob")
    assert e["EventID"] == 4625 and e["IpAddress"] == "192.0.2.5" and e["Computer"] == "WS1"


def test_spray_vs_single_typo():
    spray = [ev(4771, Status="0x18", IpAddress="192.0.2.9", TargetUserName=f"u{i}") for i in range(6)]
    assert "password_spray" in rules_of(spray)
    assert rules_of([ev(4625, IpAddress="10.0.0.2", TargetUserName="bob")]) == set()


def test_lsass_access_mask():
    assert "lsass_access" in rules_of([ev(10, SYS, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1010", SourceImage="m.exe")])
    assert not rules_of([ev(10, SYS, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1000", SourceImage="taskmgr.exe")])


def test_psexec_pipes_and_wmi():
    assert "psexec_like_pipe_over_smb" in rules_of([ev(5145, RelativeTargetName="svc-WS1-1234-stdin", IpAddress="10.0.0.5")])
    assert "wmi_spawned_shell" in rules_of([ev(1, SYS, ParentImage="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /Q /c whoami")])


def test_4720_machine_name_vs_user():
    assert "computer_account_via_4720" in rules_of([ev(4720, TargetUserName="EVIL$", SubjectUserName="bob")])
    assert rules_of([ev(4720, TargetUserName="jdoe", SubjectUserName="admin")]) == {"user_created"}


def test_scriptblock_and_com_hijack():
    assert "suspicious_scriptblock" in rules_of([ev(4104, "Microsoft-Windows-PowerShell/Operational", ScriptBlockText="[x]::MiniDumpWriteDump($h)")])
    assert "com_hijack_hkcu" in rules_of([ev(13, SYS, TargetObject="HKU\\S-1-5-21-1\\Software\\Classes\\CLSID\\{AB}\\InprocServer32\\(Default)", Image="x.exe", Details="C:\\u\\a.dll")])


def test_regressions_from_real_samples():
    # zero-padded hex as written by real DCs / Sysmon
    assert "lsass_access" in rules_of([ev(10, SYS, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x00001010", SourceImage="m.exe")])
    spray = [ev(4768, Status="0x00000006", IpAddress="::ffff:192.0.2.9", TargetUserName=f"u{i}") for i in range(5)]
    assert "password_spray" in rules_of(spray)
    # HKU\<SID>_CLASSES path form
    assert "com_hijack_hkcu" in rules_of([ev(13, SYS, TargetObject="HKU\\S-1-5-21-1_CLASSES\\CLSID\\{AB}\\InprocServer32\\(Default)", Image="x.exe", Details="d.dll")])
    # 4688 without ParentProcessName: parent rebuilt from ProcessId
    evs = [ev(4688, NewProcessId="0x0ae8", NewProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", ProcessId="0x248"),
           ev(4688, NewProcessId="0x424", NewProcessName="C:\\Windows\\System32\\calc.exe", ProcessId="0x00000ae8")]
    assert "wmi_child_process" in rules_of(evs)


def test_logon_after_failures():
    evs = [ev(4625, TargetUserName="bob", IpAddress="192.0.2.7") for _ in range(5)] + [ev(4624, TargetUserName="bob", IpAddress="192.0.2.7", LogonType="3")]
    evs[-1]["TimeCreated"] = "2026-10-11 10:00:05"
    assert "logon_after_failures" in rules_of(evs)
    assert "logon_after_failures" not in rules_of([ev(4625, TargetUserName="bob"), ev(4624, TargetUserName="bob")])


def test_special_privileges():
    assert "special_privileges_logon" in rules_of([ev(4672, SubjectUserName="alice", PrivilegeList="SeDebugPrivilege SeBackupPrivilege")])
    assert rules_of([ev(4672, SubjectUserName="SYSTEM", PrivilegeList="SeDebugPrivilege"), ev(4672, SubjectUserName="WS1$", PrivilegeList="SeDebugPrivilege")]) == set()
