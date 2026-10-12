#!/bin/sh
# EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0). Not redistributed here; downloaded on demand.
set -e; cd "$(dirname "$0")"
E=https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master
for p in "Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx" "Credential%20Access/kerberos_pwd_spray_4771.evtx" \
 "Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx" "Credential%20Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx" \
 "Defense%20Evasion/DE_1102_security_log_cleared.evtx" "Defense%20Evasion/DE_Fake_ComputerAccount_4720.evtx" "Defense%20Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx" \
 "Lateral%20Movement/LM_WMI_4624_4688_TargetHost.evtx" "Lateral%20Movement/LM_renamed_psexecsvc_5145.evtx" \
 "Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx" "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"; do
  curl -sfLO "$E/$p"; done
sha256sum *.evtx > SHA256SUMS.txt
