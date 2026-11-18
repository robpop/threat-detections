# Sensitive Browser File Access via LOLBAS Binaries

Detects a signed Microsoft .NET Framework binary, such as `RegAsm.exe`, `RegSvcs.exe`, or `MSBuild.exe`, reading sensitive browser data (saved passwords, cookies, autofill data, and the Chromium encryption key) in Microsoft Defender for Endpoint `DeviceEvents` (KQL) or in any Windows file access log source that records reads (Sigma). These binaries have no legitimate reason to touch browser profiles, so this behavior strongly suggests the process was hollowed out and is running an infostealer payload.

| | |
| --- | --- |
| **Rules** | [KQL](./sensitive_browser_file_access_via_LOLBAS_binaries.kql) (Defender XDR) · [Sigma](./sensitive_browser_file_access_via_LOLBAS_binaries.yml) (platform-agnostic, not for Defender XDR) |
| **Data sources** | KQL: Defender for Endpoint (`DeviceEvents`, `SensitiveFileRead` action type) · Sigma: Windows `file_access` events that record file reads |
| **Severity** | High |
| **MITRE ATT&CK** | [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access · [T1555.003](https://attack.mitre.org/techniques/T1555/003/) Credentials from Web Browsers · [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie<br>[TA0005](https://attack.mitre.org/tactics/TA0005/) Defense Evasion · [T1055.012](https://attack.mitre.org/techniques/T1055/012/) Process Hollowing · [T1218.009](https://attack.mitre.org/techniques/T1218/009/) Regsvcs/Regasm · [T1127.001](https://attack.mitre.org/techniques/T1127/001/) MSBuild |
| **Author** | Robert Popeleski |

## Background

Commodity .NET infostealers such as Agent Tesla, RedLine, Lumma, Vidar, and Snake Keylogger frequently use process hollowing to hide inside trusted binaries. The loader starts a signed Microsoft binary in a suspended state, replaces its memory with the stealer payload, and resumes it. To the endpoint sensor, the activity that follows appears to come from `RegAsm.exe` or a similar binary rather than from the malware.

The binaries in this detection are popular hosts because they ship with every .NET Framework install, are signed by Microsoft, and are often allowed by application control policies. Their legitimate uses (registering assemblies for COM, building projects, installing services, compiling code) never involve reading browser credential stores. A match is therefore high-signal, and this detection anchors on that behavior rather than on a specific malware family or file hash.

## Detection logic

1. Filter `DeviceEvents` to `SensitiveFileRead` events, which Defender for Endpoint records when a process reads a file it classifies as sensitive.
2. Keep events where the initiating process is one of the hollowing hosts below, matched on both the file name and the original file name from the PE version info so that renamed copies are still caught:
   `regasm.exe`, `regsvcs.exe`, `msbuild.exe`, `installutil.exe`, `applaunch.exe`, `vbc.exe`, `aspnet_compiler.exe`, `addinprocess32.exe`
3. Extract the accessed file path from `AdditionalFields` and keep events where it is inside a Chrome, Edge, Brave, Opera, or Firefox profile directory.
4. Keep events where the file is a credential or session store: `Login Data`, `Web Data`, `Cookies`, `Local State`, `key4.db`, `logins.json`, `cookies.sqlite`, or `formhistory.sqlite`.

`Local State` is included because it holds the encrypted master key that Chromium-based stealers need to decrypt `Login Data` and `Cookies`.

The Sigma version follows steps 2 to 4 against the `file_access` category. Step 1 and the path extraction in step 3 are specific to Defender, so the Sigma rule matches the `FileName` field (the full path of the accessed file) directly.

## Sigma conversion

The Sigma rule uses SigmaHQ's standard `file_access` category with the `Image`, `OriginalFileName`, and `FileName` fields. It contains nothing specific to one platform, so it can be converted with `sigma-cli` for any backend whose file access telemetry records reads, using that backend's usual pipeline.

The rule matches the process on both `Image` and `OriginalFileName`:

- `Image` catches the normal case, where the binary runs from its own path, and works with log sources that only record the process path.
- `OriginalFileName` comes from the binary's PE version information, so it still matches a renamed copy (for example `RegAsm.exe` copied to `update.exe`). Not every file access source records it, which is why it isn't the only check.

### Defender XDR: use the KQL version

**Do not convert the Sigma rule for Defender XDR.** Converting it with `sigma convert -t kusto -p microsoft_xdr` completes without errors but produces a query that never matches:

```kql
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\regasm.exe" or ...
```

The `microsoft_xdr` pipeline maps the `file_access` category to `DeviceFileEvents`, which records file creation, modification, renaming, and deletion but not reads. The table's `FileName` column also holds only the file name, not the full path, so the browser path conditions can't match either. Defender records file reads only as `SensitiveFileRead` events in `DeviceEvents`, with the accessed path inside the `AdditionalFields` JSON. Sigma can't express that extraction without a custom pipeline, so the [KQL](./sensitive_browser_file_access_via_LOLBAS_binaries.kql) version is the supported option for Defender XDR.

SigmaHQ's broader [Suspicious File Access to Browser Credential Storage](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files.yml) rule (`a1dfd976-4852-41d4-9507-dc6590a3ccd0`) alerts on any non-browser process reading these files. It covers more ground at a lower confidence level and has the same Defender conversion issue.

## Deployment

These steps apply to the KQL version in Defender XDR.

**Verify the action type first.** `SensitiveFileRead` and the shape of its `AdditionalFields` should be confirmed in your tenant before creating the rule. This query shows whether the events exist, which processes normally generate them, and a sample of the JSON:

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SensitiveFileRead"
| summarize Events = count(), Sample = take_any(AdditionalFields) by InitiatingProcessFileName
| top 50 by Events
```

Expect browsers, password managers, and backup agents. None of the hollowing hosts should appear.

**Near real-time (NRT).** The KQL query uses a single table, no joins or unions, and only operators from Microsoft's supported list (`has`, `in`, `tolower`, `parse_json`, `tostring`), so it is written to qualify for the **Continuous (NRT)** frequency. Custom detections set to NRT cannot contain comments, so **remove the comment lines in the `.kql` file before pasting the query into the rule.** If Continuous (NRT) is not offered in the frequency list, check the query for comments first.

**Response actions.** The query returns `DeviceId`, `InitiatingProcessSHA256`, and `InitiatingProcessAccountSid`, which support device isolation, file quarantine, and user actions. Start the rule as alert-only and enable automated actions only after it has run long enough to confirm a low false positive rate in your environment.

## False positives

- Malware analysis sandboxes and detonation labs onboarded to Defender for Endpoint.
- Red team or penetration testing activity that uses these binaries to run tooling.
- In-house build or test automation that runs through `MSBuild.exe` and deliberately reads a browser profile, such as browser test harnesses. This is rare and should be excluded narrowly by device and command line.

## Known blind spots

- **Sensitive file coverage:** `SensitiveFileRead` only fires for files that Defender for Endpoint classifies as sensitive. Browser files outside that classification will not generate events.
- **Other hollowing hosts:** stealers injected into binaries not on the list (for example `explorer.exe`, `dllhost.exe`, or an unrelated third-party process) are not detected.
- **Injection into the browser:** stealers that inject into the browser process itself, or that use the browser's remote debugging interface, read the data as the browser and do not match. This is increasingly common as stealers work around Chrome's app-bound encryption.
- **Unlisted browsers:** Vivaldi, Yandex, and other Chromium-based browsers with their own profile paths are not covered. Add their paths if they are used in your environment.
- **Indirect reads:** a stealer that copies the files using another process (such as `esentutl.exe`, a shadow copy, or a raw disk read) and then reads the copy will not match.
- **Non-Windows devices:** the detection only covers Windows file paths and .NET Framework binaries.
- **Log source coverage (Sigma version):** the rule only works where file access logging records reads of these paths. Sysmon does not log file reads, so a Sysmon-only environment needs object access auditing (SACLs on the browser profile folders) or another EDR source mapped to `file_access`.

## Triage

Review the initiating process tree to identify the parent that launched the hollowing host, which is often a script, an Office document, a downloaded executable, or a scheduled task. A host binary with an empty or bare command line is a strong sign of hollowing, since legitimate use always includes arguments. Check whether the same process made outbound network connections in `DeviceNetworkEvents` shortly after the read, which would indicate data exfiltration.

If the activity is confirmed malicious, isolate the device, then treat every credential and session stored in the affected browser profiles as compromised: reset the user's passwords, revoke active sessions and refresh tokens for their accounts, and check for sign-ins from unfamiliar locations. Search for the same parent file hash on other devices to find additional infections.
