# Security Model

## Goals

Tashev Guard should help a device owner inspect observable security signals without becoming another source of remote access or data collection.

## Trust boundaries

### Desktop dashboard

The local HTTP service binds to `127.0.0.1`. It is not intended to be reachable from the LAN or internet.

### Collectors

Collectors query operating-system state. They should prefer read-only APIs and commands. Elevated privileges should only be introduced for a feature that cannot be implemented safely without them.

### Baseline

The baseline is a local comparison aid. It is not a signed trust database and should never be interpreted as proof that everything present at baseline time is safe.

### Risk engine

Risk labels are heuristics. Every finding should expose evidence: process, PID, path, listener, remote host, persistence entry, signature information, or similar observable data.

## Non-goals

The current preview does not claim to:

- replace endpoint detection and response products;
- prove attribution to a real-world person;
- detect every malware family;
- inspect encrypted payload contents;
- silently remediate a device;
- provide forensic guarantees.

## Safe-action rule

Destructive or connectivity-changing actions must be explicit, narrow, reversible where possible, and separated from passive detection.

## Network privacy

Reverse DNS uses the operating system's resolver. The project currently avoids uploading a user's complete connection list to a third-party reputation API.

## Android

Android network capture will use `VpnService` only with a real forwarding path. Packet capture without forwarding can interrupt traffic and is not considered production-safe.

## Future device pairing

Any multi-device feature must use authenticated pairing and must never make a local agent discoverable to arbitrary internet clients by default.
