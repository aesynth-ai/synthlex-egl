# Security Policy -- ClawLab

ClawLab is an **autonomous systems experiment**. The primary risk is not "bugs" in the usual sense -- it's **execution authority**: tool execution, side effects, and credential misuse.

This repo is not intended for production deployment.

## Reporting a vulnerability

Please report security issues **privately**.

- Preferred: open a **private security advisory** (GitHub Security Advisories), if enabled for this repo.
- Otherwise: email the maintainer(s) directly using the contact method provided out-of-band.

Include:
- what you found
- steps to reproduce
- expected vs actual behavior
- logs/artifacts if safe to share (do **not** include real tokens/keys)

## Do not run with real credentials

**Never** run ClawLab agents with:
- production API keys
- cloud provider credentials
- personal accounts containing real data
- credentials that can spend money or mutate systems

Use **sandbox identities** only.

## Containment rules (required)

When running ClawLab:
- Bind network to **loopback-only** (`127.0.0.1` / `localhost`)
- No external exposure (no public ports, no tunneling)
- No OS privilege escalation
- No background automation
- No persistence mechanisms unless explicitly part of a test
- Prefer **permit-bound execution** with EGL when executing tools

If any invariant is violated: **stop**, capture raw artifacts, and classify the anomaly.

## Known high-risk areas

- Tool execution paths (filesystem / network / process)
- URL canonicalization edge cases
- Retry / oscillation loops that amplify side effects
- Silent surface expansion (new tools / new permissions)
- Budget or model routing that escalates unexpectedly

## Supported versions

This repo is an evolving experiment; there is no formal version support matrix.
Security fixes are handled case-by-case and may require protocol changes.

