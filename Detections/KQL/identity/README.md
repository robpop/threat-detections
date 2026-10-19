# MFA Fatigue Followed by Successful Sign-In

Detects a likely account compromise in Microsoft Entra ID: a burst of failed or denied MFA prompts for a user, followed by a successful sign-in from one of the same IP addresses that generated those prompts.

| | |
| --- | --- |
| **Query** | [`mfa_fatigue_detection.kql`](./mfa_fatigue_detection.kql) |
| **Platform** | Microsoft Defender XDR custom detection (Microsoft Sentinel) |
| **Data source** | `SigninLogs` (Entra ID interactive sign-ins) |
| **Severity** | Low |
| **MITRE ATT&CK** | [T1621 – Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/) (Credential Access)<br>[T1078.004 – Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) (Initial Access) |
| **Author** | Robert Popeleski |

## Background

In an MFA fatigue attack, the attacker already has a user's password. They repeatedly sign in to trigger MFA push notifications, hoping the user eventually approves one out of annoyance or confusion. Because the attacker's own sign-in attempts generate the prompts, the failed MFA events and the eventual successful sign-in usually share the attacker's IP address.

## Detection logic

1. Find users with at least 5 sign-ins that failed the strong-authentication step (`ResultType` 500121) within the rule's lookback window.
2. Find successful sign-ins (`ResultType` 0) for those users.
3. Alert when a successful sign-in:
    - occurs after the first MFA failure,
    - occurs no more than 10 minutes after the last MFA failure, and
    - comes from an IP address that also generated one of the failures.
4. Return one alert per user, based on the first matching success.

The success is also flagged when Entra ID Protection marks its IP as anonymized (`anonymizedIPAddress`). This raises confidence but isn't required, since many attackers use residential proxies or ordinary hosting IPs. Legitimate users on VPNs can also trigger this flag.

### Tunable parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `mfaThreshold` | 5 | Minimum MFA failures per user in the lookback window |
| `maxGapAfterLastFailure` | 10m | How long after the last failure a success still counts |

## Requirements

- Entra ID sign-in logs connected to Microsoft Sentinel, with Sentinel onboarded to the Defender portal.
- Microsoft Sentinel Contributor (or higher) to create the rule.
- Entra ID P2 for the `RiskEventTypes` / `RiskLevelDuringSignIn` fields. The rule works without P2, but `IsAnonymousIP` will always be false.

## Rule configuration

| Setting | Value |
| --- | --- |
| Frequency | Custom: every 15 minutes |
| Lookback | 1 hour |
| Alert title | `Suspected MFA fatigue compromise: {{UserPrincipalName}}` |
| Alert description | `User had {{MfaFailureCount}} failed or denied MFA attempts, then signed in successfully to {{AppDisplayName}} from {{SuccessIP}}, the same IP that generated the failures.` |
| Impacted asset | Account → `UserId` (object ID), `UserPrincipalName` |
| Related evidence | IP → `SuccessIP` |
| Custom details | `TimeToCompromiseMinutes`, `IsAnonymousIP`, `FailureDetails`, `AppDisplayName`, `ClientAppUsed`, `RiskLevelDuringSignIn`, `FirstFailure`, `CorrelationId` |
| Automated actions | None (alert only) |

The query contains no time filter. Defender custom detections prefilter data by the rule's lookback using ingestion time, so an event-time filter would drop late-arriving sign-ins. For hunting in Advanced Hunting, add `| where TimeGenerated >= ago(1h)` (or longer) to both subqueries.

Continuous (NRT) frequency isn't supported because the query uses a join.

## Triage

1. **Ask the user** whether they approved an MFA prompt at `TimeGenerated` and whether they were trying to sign in during the failures. An unexpected approval is a strong indicator of compromise.
2. **Check the IP and location.** Is `SuccessIP` a known corporate, VPN, or home address for this user? Is `IsAnonymousIP` true?
3. **Review the failure reasons** in `FailureDetails`. Repeated "user declined" or "did not respond" responses fit an MFA fatigue pattern. Other errors may indicate a device or enrollment problem.
4. **Look for follow-on activity** from the session: new inbox rules, mail forwarding, new MFA methods, OAuth consents, unusual file access, or other anomalous user activity.

## Response

If the user can't confirm the activity:

1. Revoke the user's sessions and refresh tokens.
2. Reset the password.
3. Remove any MFA methods or devices the user doesn't recognize.
4. Remove malicious inbox rules or forwarding and other persistence mechanisms.
5. Investigate how the password was obtained (phishing, reuse, infostealer).

## False positives

- **Legitimate users with MFA trouble.** A user who misses or declines several prompts (phone on silent, app not opening) and then succeeds from the same office or home IP matches this logic. This is the most common false positive; check the IP against the user's normal locations.

## Known blind spots

- **Rotating infrastructure.** Attackers who send prompts from one IP and complete sign-in from another won't match.
- **Low-volume attacks.** Fewer than `mfaThreshold` prompts before the user approves.
- **MFA bypass.** Adversary-in-the-middle phishing and token theft don't generate MFA failures at all.
- **Non-interactive sign-ins** (`AADNonInteractiveUserSignInLogs`) are not covered.

## Changelog

| Version | Change |
| --- | --- |
| 1.0 | Initial release |