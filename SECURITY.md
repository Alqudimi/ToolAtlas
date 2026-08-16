# Security Policy

## Scope

ToolAtlas is a static analyzer. Its security boundary is intentionally narrow: it parses bounded local data and does not execute commands, make network requests, or call model providers.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Email the maintainer at `eng7mi@gmail.com` with a description, reproduction steps, affected version, and suggested mitigation. Do not include real secrets or personal data. Reports will be acknowledged as soon as practical and coordinated through a private disclosure process.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Safe-use notes

ToolAtlas is not a sandbox, permission boundary, gateway, or malware detector. A clean report does not prove that a tool is safe. Use operating-system or container isolation for untrusted code and review generated policies before enforcement.
