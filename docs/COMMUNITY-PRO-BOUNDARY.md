# Community / Pro Boundary

This document is an engineering rule for keeping the open-source and commercial editions cleanly separated.

## Community owns

- operating-system collectors;
- local baseline;
- explainable local risk engine;
- localhost dashboard;
- local event history;
- local notifications;
- Android local audit;
- public schemas and protocol definitions needed to communicate with optional external services.

## Pro owns

- hosted control plane;
- user accounts and subscriptions;
- device fleet management;
- organization/team management;
- long-term centralized storage;
- cross-device correlation;
- remote policy orchestration;
- commercial threat-intelligence feeds;
- notification delivery infrastructure;
- business reporting;
- enterprise integrations.

## Boundary rule

Pro should consume Community through an explicit API/protocol boundary. Do not copy private Pro business logic into the public repository, and do not make Community require private Pro code for its local core functionality.

## Security rule

A Pro connection must be opt-in. The Community agent must never expose a new inbound internet port by default. Remote connectivity should be initiated outbound by the user's device after authenticated pairing.

## Contribution rule

Any public contribution that could later be useful in Pro should only be merged after the contributor acknowledges [CLA.md](../CLA.md).
