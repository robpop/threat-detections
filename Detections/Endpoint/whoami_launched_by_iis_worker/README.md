# Whoami Executed by IIS Worker Process

Detects `whoami.exe` launched directly by the IIS worker process (`w3wp.exe`), a strong sign that an attacker is running commands through a web shell or an exploited web application.

| | |
| --- | --- |
| **Rules** | [KQL](./whoami.kql) (Microsoft Sentinel) · [Sigma](./whoami.yml) · [Wazuh](./whoami.xml) |
| **Data source** | Windows process creation: Security Event 4688 (KQL), Sysmon Event 1 (Wazuh), generic `process_creation` (Sigma) |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell · [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery |
| **Author** | Robert Popeleski |

## Background

`w3wp.exe` is the IIS worker process that serves requests for a web application. In normal operation it rarely starts other programs. When an attacker plants a web shell or exploits a vulnerable application, the commands they send run as children of `w3wp.exe`. One of the first is usually `whoami`, to see which account the application runs as and what privileges they have.

## Detection logic

1. Find process creation events where the new process is `whoami.exe`.
2. Alert when its parent process is `w3wp.exe`.

## False positives

Possible sources are web applications or monitoring tools that shell out to `whoami` to check their own identity. Confirm with the application owner and exclude by application pool or site if needed.

## Known blind spots

- Commands run through a shell (`cmd.exe /c whoami`), where the parent of `whoami.exe` is `cmd.exe` rather than `w3wp.exe`
- Renamed copies of `whoami.exe`
- Other ways to get the same information (`$env:USERNAME`, `net user`, .NET identity calls) and other discovery commands (`ipconfig`, `systeminfo`, `net`)
- Web servers other than IIS (Apache, Tomcat, nginx)
- Hosts without process creation logging (Security 4688 auditing or Sysmon)

## Triage

Identify the site and application pool behind the `w3wp.exe` process, then review IIS logs around the alert time for the request that triggered it. Check the web root for recently created or modified script files (`.aspx`, `.ashx`, `.asp`) and review other child processes of `w3wp.exe`. If a web shell is confirmed, isolate the server, remove the shell, patch the exploited vulnerability, and rotate credentials accessible to the application pool identity.
