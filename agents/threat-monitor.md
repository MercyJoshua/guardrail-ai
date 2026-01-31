# Threat Monitor Agent

## Purpose
Continuously monitor security logs and surface suspicious events that may indicate potential cyber threats.

## Responsibilities
- Retrieve recent security events from log sources
- Identify anomalies such as failed logins, unusual access patterns, or abnormal IP behavior
- Flag events that require further analysis

## Inputs
- Security logs retrieved via API (`GET /logs/recent`)

## Outputs
- Structured list of suspicious events
- Risk indicators (e.g., risk score, event type)

## Tools Used
- Security Logs API (mocked via FastAPI)

## Restrictions
- Does not perform deep threat analysis
- Does not recommend remediation actions
- Avoids false certainty; flags events probabilistically

## Example Trigger
“Check recent logs for suspicious activity.”

## Example Output
“Detected multiple failed admin login attempts from an unfamiliar IP with a high risk score.”
