# Security Policy

## Reporting a vulnerability

Please report vulnerabilities via GitHub's *Private vulnerability reporting*
(Security tab of this repository). Do not open public issues for suspected
vulnerabilities.

Please include: affected component/endpoint, reproduction steps, and any
proof-of-concept details. Reports are acknowledged within 7 days.

## Scope

- CLI, HTTP API, scheduler, webhooks, and Docker image of this tool.
- The bundled Mozilla root store (`internal/roots/ca.pem`) is upstream
  content; report upstream issues to Mozilla instead.

## Handling

- Scan outputs may contain information about live TLS endpoints; do not
  publish scan results from networks you do not own.
- Never commit real device configurations, scan databases, or credentials
  when using this tool locally.
