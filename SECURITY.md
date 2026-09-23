# Security Policy

Tashev Guard is a security-sensitive project. Please do **not** publish vulnerability details in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting / Security Advisory flow for this repository:

https://github.com/tashev11/tashev-guard/security/advisories/new

Please include:

- affected version or commit;
- platform and OS version;
- exact reproduction steps;
- impact;
- whether exploitation requires local access, elevated privileges, or user interaction;
- a minimal proof of concept when safe to share privately.

## Scope

High-priority reports include vulnerabilities that could:

- expose local monitoring data to another machine;
- allow unauthenticated access to the local API from outside the host;
- execute commands unexpectedly;
- create unsafe persistence;
- leak secrets or system information;
- turn a read-only audit path into an unintended write/action path;
- break network connectivity through a future VPN/forwarding feature.

## Supported versions

The project is currently in preview. Security fixes target the latest version on `main` and the latest published preview release.

## Disclosure

Please allow time for investigation and a fix before public disclosure. We will document confirmed security fixes in release notes.
