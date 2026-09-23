# Tashev Guard Device Protocol (Draft)

Status: **draft / v0**

This public document defines the interoperability boundary between Tashev Guard Community agents and optional external services such as Tashev Guard Pro.

The protocol is intentionally public. Private business logic, subscriptions, threat-intelligence rules and hosted service implementation are not part of this specification.

## Principles

- outbound connection from the user's device;
- explicit pairing initiated by the user;
- unique revocable identity per device;
- TLS for transport;
- no reusable pairing code after enrollment;
- no cloud requirement for Community local mode;
- remote actions must be explicit, authenticated and auditable;
- protocol version must be negotiated.

## Device identity

After pairing, each device should have:

- stable random device ID;
- device public key;
- private key stored using OS-protected storage where available;
- revocation state;
- human-readable device name supplied or approved by the user.

Do not use MAC addresses, serial numbers or other hardware identifiers as authentication secrets.

## Pairing sketch

```text
User opens Pro dashboard
        |
        v
One-time pairing code / QR
        |
        v
Community Agent
        |
        | outbound TLS
        v
Pair endpoint
        |
        +--> code consumed
        +--> device key registered
        +--> long-lived device credential returned
```

A pairing code must expire and must not be usable as a permanent credential.

## Envelope

Future messages should use a versioned envelope such as:

```json
{
  "protocol": "tg/1",
  "type": "device.heartbeat",
  "message_id": "uuid",
  "device_id": "uuid",
  "sent_at": "RFC3339 timestamp",
  "payload": {}
}
```

## Initial message classes

- `device.hello`
- `device.heartbeat`
- `device.status`
- `event.security`
- `command.request`
- `command.result`
- `device.revoke`

## Remote command rule

The first protocol versions should be conservative. Read-only requests are preferred.

Any command that can kill a process, change a firewall, alter persistence, modify network settings, or affect connectivity must:

1. be individually authenticated;
2. be represented in the local audit log;
3. have an explicit policy allowing it;
4. require local confirmation unless the user has deliberately enabled a managed policy that permits the exact action;
5. return a structured result.

## Privacy

A device should send the minimum data necessary for the enabled Pro feature. Community local mode sends nothing to Pro unless the user pairs the device.

Fields that can contain usernames, full paths, remote IPs or process command lines must be treated as potentially sensitive.

## Compatibility

Protocol additions should be backward-compatible within a major protocol version. Breaking wire changes require a new protocol major version.
