# Roadmap

Tashev Guard is currently a preview.

## Near term

- [ ] Runtime verification on a real Windows machine
- [ ] Signed macOS and Windows builds
- [ ] Better persistence inventory on both desktop platforms
- [ ] Explainable process reputation using local evidence first
- [ ] Exportable redacted audit report
- [ ] Manual investigate / block actions with safe undo
- [ ] Android physical-device smoke test
- [ ] Release-signed Android APK

## Android networking

- [ ] Foreground `VpnService` lifecycle
- [ ] IPv4 / IPv6 packet parser
- [ ] DNS visibility
- [ ] TCP/UDP forwarding engine
- [ ] Connectivity regression tests
- [ ] App attribution where Android APIs safely permit it
- [ ] Per-destination baseline
- [ ] Explicit allow/block rules
- [ ] Coexistence strategy for users who already use a VPN

A packet-capture VPN will not ship until forwarding is verified. A TUN reader without forwarding is not an acceptable implementation because it can break connectivity.

## Multi-device

- [ ] Secure pairing of a user's own devices
- [ ] End-to-end authenticated device transport
- [ ] Optional self-hosted hub
- [ ] Optional hosted dashboard
- [ ] Telegram / other notification connectors without storing tokens in source code

## iOS

iOS will be treated as a separate capability profile. Tashev Guard will not claim unrestricted process or socket visibility that normal iOS apps do not have.
