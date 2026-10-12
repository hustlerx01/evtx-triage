# Interview talking points: evtx-triage

1. **Real data beats fixtures.** My unit tests passed and the first real run still scored 7/11. Every miss was a format detail: zero-padded hex, `_CLASSES` registry paths, missing parent fields on old 4688 events, and spray showing up as 4768/0x6. Each one is now a regression test.
2. **Kerberos spray.** 4771 with 0x18 is a bad password. 4768 with 0x6 is an unknown user, which means enumeration. Many distinct accounts from one IP in a short window is a spray. NTLM spray shows up as 4625 / 4776 instead.
3. **LSASS access masks.** 0x1010 / 0x1410 (PROCESS_VM_READ | QUERY_LIMITED_INFORMATION) is what mimikatz `sekurlsa` uses. EDRs and AV legitimately touch lsass, so you'd allow-list SourceImage by signer.
4. **PsExec without the name.** Renamed PsExec still creates `*-stdin/-stdout/-stderr` pipes (Sysmon 17/18, 5145 on IPC$). Detecting the behaviour survives renaming.
5. **Honesty about overfitting.** 11/11 after tuning on the same 11 samples tells me nothing about generalisation. I'd hold out the OTRF Security-Datasets for a real score.
6. **Triage output.** A timeline CSV is what you hand to IR. Sorting by time across files on the same host rebuilds the kill chain.
