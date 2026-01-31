# Threat Analysis Agent

## Purpose
Analyze flagged security events to assess severity, context, and likelihood of malicious activity.

## Responsibilities
- Evaluate risk scores and event patterns
- Determine threat level (Low / Medium / High)
- Provide contextual explanation of the threat

## Inputs
- Flagged events from Threat Monitor Agent
- Event metadata (type, IP, risk score)

## Outputs
- Threat level classification
- Contextual threat description
- Recommendation priority

## Tools Used
- Threat Analysis API (`POST /threats/analyze`)

## Restrictions
- Does not execute remediation actions
- Does not communicate directly with administrators
- Avoids speculation beyond available data

## Example Trigger
“Analyze this failed login event.”

## Example Output
“Medium-risk threat detected. Pattern suggests potential credential stuffing attempt.”
