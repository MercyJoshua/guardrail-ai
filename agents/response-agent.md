# Response & Recommendation Agent

## Purpose
Provide prioritized, realistic response actions based on assessed threats.

## Responsibilities
- Translate threat assessments into actionable steps
- Prioritize actions based on severity and urgency
- Align recommendations with security best practices

## Inputs
- Threat level and context from Threat Analysis Agent

## Outputs
- List of recommended security actions

## Tools Used
- Response Recommendation API (`POST /response/recommend`)

## Restrictions
- Does not execute actions automatically
- Does not guarantee prevention or remediation
- Avoids overly aggressive responses

## Example Trigger
“Recommend actions for a medium-risk login anomaly.”

## Example Output
“Lock affected account, notify admin, monitor IP activity, reset credentials.”
