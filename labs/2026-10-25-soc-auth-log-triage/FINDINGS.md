# SOC Lab Findings, October 25, 2026

## Objective and scope

Analyzed 15 synthetic authentication events. No real accounts, hosts, or networks were tested.

## Results

- 10 failed and 5 successful login events.
- 3 alerts: 2 possible brute-force patterns and 1 success-after-failures pattern.
- `198.51.100.23`: four failed admin logins from 14:01 to 14:04 UTC, followed by success at 14:05 UTC.
- `203.0.113.77`: five failed root logins from 14:08 to 14:15 UTC, no success observed.
- `192.0.2.10`: normal successful logins, no alerts.

## Assessment

The success after repeated failures warrants priority investigation, but does not prove compromise. The repeated failures without success warrant a brute-force review.

## Validation

- Analyzer executed on the synthetic CSV.
- Four unit tests passed, including a sliding-window boundary test and malformed-event validation.

## Next improvements

1. Detect password spraying across IPs.
2. Parse sanitized Windows Event IDs 4624/4625 or SSH logs.
3. Tune thresholds against a normal authentication baseline.
4. Add MFA, device, and approved-automation context.

## Employer-ready summary

Developed and tested a Python SOC authentication-log triage prototype using synthetic data. Implemented rolling-window failure detection, correlated follow-on successful logins, exported JSON alerts, and documented investigation priorities and false-positive limitations.

**Attribution:** Initial sample and code were prepared with AI assistance. Review and independently refine before presenting as personal implementation.
