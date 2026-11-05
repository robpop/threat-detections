# Device Connection to Threat Intel Indicator

Detects a device communicating with an active threat intelligence indicator which can be a remote IP address, hostname, or URL in Microsoft Defender for Endpoint network and device events that matches an indicator in the Microsoft Sentinel `ThreatIntelIndicators` table. The Wazuh rules match Sysmon network connection events against indicator lists that you supply.

| | |
| --- | --- |
| **Rules** | [KQL](./threat_intel_device_connect.kql) (Defender XDR / Sentinel) · [Sigma](./threat_intel_device_connect.yml) (two rules, with [pySigma pipeline](./threat_intel_pipeline.yml)) · [Wazuh](./threat_intel_device_connect.xml) (Sysmon, requires CDB lists) |
| **Data sources** | KQL / Sigma: Defender for Endpoint (`DeviceNetworkEvents`, `DeviceEvents`) and Sentinel threat intelligence (`ThreatIntelIndicators`) · Wazuh: Sysmon Event ID 3 (network connection) |
| **Severity** | Medium |
| **MITRE ATT&CK** | [TA0011](https://attack.mitre.org/tactics/TA0011/) Command and Control · [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol |
| **Author** | Robert Popeleski |

## Background

Threat intelligence feeds supply IP addresses, domains, and URLs tied to known malicious infrastructure, such as command and control servers, phishing sites, and malware delivery hosts. A device connecting to one of them may indicate malicious activity. This detection matches against indicators rather than detecting a specific technique, so its quality depends on the quality of the feeds behind it.

## Detection logic

1. Build a list of indicators from `ThreatIntelIndicators`: keep only the newest version of each indicator, drop inactive (expired or revoked) indicators, convert to lowercase, strip any `http://` or `https://` prefix and trailing slash, and remove empty values and duplicates.
2. Alert when a `DeviceNetworkEvents` event has a `RemoteIP` or `RemoteUrl` on that list (case-insensitive).
3. Alert when a `DeviceEvents` event (SmartScreen, network protection, browser launches) has a `RemoteIP` or `RemoteUrl` on that list.

Exact implementation differs by platform. The Wazuh version only covers step 2 by using Sysmon network connection events (Event ID 3) and indicator lists you supply.

## Sigma conversion

The Sigma version is two rules, one per table (`DeviceEvents` and `DeviceNetworkEvents`), and converts to two separate queries, so it deploys as **two custom detections** since Sigma can't write a KQL `union`.

Sigma can't express a lookup against another table, so both rules use an `|expand` placeholder (`%ThreatIntelIOCs%`). The included pipeline fills the placeholder in with a KQL lookup and adds the indicator `let` block to each query.

The pipeline also maps `service: deviceevents` to the `DeviceEvents` table as `deviceevents` is not part of SigmaHQ's taxonomy.

Requirements: `sigma-cli` and `pySigma-backend-kusto`. The Kusto backend does not support pySigma 2.x yet, so explicitly define the versions:

```
pip install "pysigma<2" "sigma-cli<4" pysigma-backend-kusto
```

Convert both rules:

```
sigma convert -t kusto -p threat_intel_pipeline.yml -p microsoft_xdr threat_intel_device_connect.yml
```

Pass `threat_intel_pipeline.yml` alongside `microsoft_xdr`. Its priority (5) makes it run before `microsoft_xdr` (10), which is required for the `DeviceEvents` table mapping.

The output is two complete queries, each beginning with the same `let ThreatIntelIOCs = ...;` block, one for `DeviceNetworkEvents` and one for `DeviceEvents`. Test each in Advanced Hunting separately, then create a custom detection from each.

It is important to note that `ThreatIntelIndicators` is only available in Defender Advanced Hunting when a Sentinel workspace is connected to the Defender portal.

## Wazuh dependencies

The Wazuh rules check Sysmon network connections against two CDB lists. The rules reference the lists but don't create or fill them. Therefore, building and maintaining them is up to you.

| Rule | Field | List | Lookup |
| --- | --- | --- | --- |
| 100900 | `win.eventdata.destinationIp` | `etc/lists/threat-intel-ips` | `address_match_key` |
| 100901 | `win.eventdata.destinationHostname` | `etc/lists/threat-intel-domains` | `match_key` |

Requirements:

- **Sysmon on the endpoints** with network connection logging (Event ID 3) enabled, and the Wazuh agent collecting the `Microsoft-Windows-Sysmon/Operational` channel.
- **Two list files** on the Wazuh manager, at `/var/ossec/etc/lists/threat-intel-ips` and `/var/ossec/etc/lists/threat-intel-domains`.

  Lookups are exact matches, so store domains lowercase, without `http://`, `https://`, paths, or trailing slashes. Keys that contain a colon, such as IPv6 addresses, must be wrapped in quotation marks. 

- **Both lists registered** in the `<ruleset>` block of `/var/ossec/etc/ossec.conf`

- **A process to keep the lists current**, such as a scheduled export of active indicators from your threat intel platform. The lists are only as fresh as your last update.

- **A Wazuh manager restart** after creating or changing either list.

Rule IDs 100900 and 100901 are in Wazuh's custom range (100000–120000). Change them if they conflict with existing rules.

## False positives

- Indicators that are shared infrastructure, such as CDN, cloud provider, or shared hosting IPs, which match large amounts of legitimate traffic.
- Sinkholed domains still listed in a feed.
- Security tools (EDR, proxies, sandboxes, scanners) that contact known-bad infrastructure as part of normal operation.

## Known blind spots

- **Subdomains:** an indicator for `evil.com` does not match `cdn.evil.com`.
- **CIDR ranges:** indicators like `203.0.113.0/24` do not match individual IPs (Wazuh should be an exception).
- **URL indicators against hostnames:** `RemoteUrl` in `DeviceNetworkEvents` is usually only a hostname, so full-URL indicators mostly match only in `DeviceEvents`.
- **DNS-only activity:** a domain that is resolved but never connected to produces no `RemoteUrl` to match.
- **Indicator time range:** indicators last ingested before the query's time range may not be included in the list.
- **Device-side URL format (Sigma version):** device `RemoteUrl` values are not normalized (Sigma cannot transform a field before comparing it), so a URL logged with `https://` or a trailing slash will not match the normalized indicator.
- **Duplicate alerts (Sigma version):** activity logged in both tables can raise one alert from each of its two detections.
- **Hostname source (Wazuh version):** Sysmon fills `DestinationHostname` from a DNS lookup of the destination IP, so it is often empty or a CDN/hosting name rather than the domain the process requested.
- **URL indicators (Wazuh version):** only IPs and hostnames are compared; full-URL indicators are not used.
- **List freshness (Wazuh version):** new or revoked indicators take effect only after the lists are updated and the manager restarts.

## Triage

Identify the initiating process and account on the device, and look up the matched value in `ThreatIntelIndicators` (in Defender environments) to see the indicator's source, confidence, and description. Check whether other devices contacted the same indicator. If the process is unexpected or the indicator is high confidence, isolate the device and investigate for follow-on activity, such as new persistence, additional outbound connections, or downloaded files. If the match is shared infrastructure or a known security tool, add a narrow exclusion.
