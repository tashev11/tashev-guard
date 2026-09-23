# Community and Commercial Editions

Tashev Guard uses an **open-core** product model.

## Tashev Guard Community

Repository: `tashev11/tashev-guard`

License: **GPL-3.0-only**

Community includes the device-side security visibility layer:

- local network connections and listeners;
- process and PID visibility;
- remote-session and remote-control indicators;
- persistence/autostart inventory;
- local baseline and local history;
- local dashboard;
- local notifications;
- Android local audit;
- public protocol specifications needed for interoperability.

Community is intended to remain useful on its own and does not require a Tashev Guard cloud account.

## Tashev Guard Pro

Tashev Guard Pro is developed separately and is **not part of this GPL repository**.

Commercial functionality may include:

- multi-device dashboard;
- secure device pairing;
- hosted or self-hosted control plane;
- long-term history and fleet analytics;
- Telegram / MAX / other alert delivery;
- organization and team management;
- business policies;
- managed response workflows;
- commercial threat intelligence;
- reporting and audit exports;
- enterprise APIs and integrations;
- commercial detection/risk rules.

## Technical boundary

Community and Pro communicate through explicit versioned interfaces.

```text
Community Agent
      |
      | authenticated versioned protocol
      v
Pro Gateway / Hub
      |
      +--> Pro Dashboard
      +--> Alerts
      +--> Teams / Policies
      +--> Long-term analytics
```

The public agent should not depend on private Pro implementation details to perform its core local security functions.

## Contributions

Public contributions are accepted under the terms in [CLA.md](CLA.md). The CLA allows accepted contributions to remain GPL in Community while also permitting their use in separately licensed Tashev Guard offerings.

## Commercial licensing

Organizations that want to embed, redistribute, integrate, or license Tashev Guard under terms different from GPL-3.0 may request a separate commercial agreement from the project owner.

No commercial license is granted by this document itself.
