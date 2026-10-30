# MFA Fatigue Followed by Successful Sign-In

Detects a likely account compromise in Microsoft Entra ID: a burst of failed or denied MFA prompts for a user, followed by a successful MFA sign-in for the same user from the same IP address.

| | |
| --- | --- |
| **Rules** | [KQL](./mfa_fatigue_followed_by_success.kql) (Defender XDR / Sentinel) · [Sigma](./mfa_fatigue_followed_by_success.yml) (v2 correlation) · [Wazuh](./mfa_fatigue_followed_by_success.xml) |
| **Data source** | Entra ID interactive sign-in logs (`SigninLogs`) |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1621](https://attack.mitre.org/techniques/T1621/) MFA Request Generation · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts |
| **Author** | Robert Popeleski |

## Background

In an MFA fatigue attack, the attacker already has the user's password and repeatedly triggers MFA push notifications until the user approves one. Because the attacker's own sign-ins generate the prompts, the failures and the eventual success usually share the attacker's IP address.

## Detection logic

1. Find sign-ins that failed the MFA step (`ResultType` 500121).
2. Find successful sign-ins (`ResultType` 0) that required MFA, excluding those satisfied by an existing token.
3. Alert when at least 5 failures are followed shortly afterward by a success, for the same user and the same IP.

Default windows: 5+ failures within 10–20 minutes, with the success following within 10–20 minutes. Exact values differ slightly by platform and are set as parameters in each rule.

## False positives

Users with MFA trouble (phone on silent, app not opening) who miss or decline several prompts and then succeed from their normal office or home IP. Check the IP against the user's usual locations.

## Known blind spots

- Attackers who send prompts from one IP and complete sign-in from another
- Fewer than 5 prompts before approval, or attempts spread beyond the time windows
- Adversary-in-the-middle phishing and token theft, which bypass MFA entirely
- Non-interactive sign-ins (`AADNonInteractiveUserSignInLogs`)

## Triage

Confirm with the user whether they approved the prompt, check the IP against their known locations, and review the session for follow-on activity: new inbox rules, mail forwarding, new MFA methods, or OAuth consents. If the activity is unconfirmed, revoke sessions, reset the password, and remove unrecognized MFA methods.
