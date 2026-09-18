# Security Policy

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** (the **Security** tab of this repository → *Report a vulnerability*) — this is the preferred channel and keeps the report confidential.

As a fallback, contact the maintainer privately via [hobbs136](https://github.com/hobbs136) (e.g. via a direct contact listed on that profile) and include `security` in the subject.

**Please do not open a public issue, and do not disclose the problem publicly before a fix has been released.**

When reporting, include:

- affected component / endpoint / crate, and the commit or version you tested against;
- reproduction steps (a minimal proof of concept is ideal);
- your assessment of the impact.

Please do not include real credentials, tokens, or production data in reports.

## Scope

This policy covers **this repository only** (dbmaster-server): its HTTP API surface (auth, workspaces, automation, license activation), the DB gateway (`/api/gw/*`), the MCP endpoint, webhook delivery, SSH tunneling, the credential vault, and the bundled scripts/tests.

In scope (non-exhaustive): authentication or authorization bypass, credential-vault or key-handling weaknesses, SQL/command injection through any server-mediated surface, entitlement/license bypass that defeats the official activation model, SSRF via webhook or connection targets, and secrets leakage in logs or error responses.

The desktop client ([github.com/hobbs136/dbmaster](https://github.com/hobbs136/dbmaster)) and the purchase site are separate codebases — report issues through their respective channels.

## What to expect

Reports are triaged by the maintainer as quickly as possible. You'll receive an acknowledgement, and follow-ups as diagnosis and a fix progress. Once a fix is released, you are welcome to be credited (opt-in) in the release notes.
