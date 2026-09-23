# Contributing to Tashev Guard

Thanks for helping improve Tashev Guard.

## Principles

Changes should preserve these project rules:

- local-first by default;
- no hidden telemetry;
- least privilege;
- findings must be explainable;
- no automatic destructive action without explicit user intent;
- do not label a process as malware without evidence;
- do not weaken localhost-only defaults;
- do not add secrets, credentials, personal data, or real user telemetry to tests.

## Development

Desktop:

```bash
npm test
npm run scan
```

Android:

```bash
cd android
./gradlew --no-daemon assembleDebug lintDebug
```

Before opening a PR:

1. keep the change focused;
2. add or update tests where practical;
3. run `git diff --check`;
4. document security-impacting behavior;
5. update README/docs when user-visible behavior changes.

## Pull requests

Describe:

- what changed;
- why it changed;
- platforms affected;
- verification performed;
- security/privacy implications;
- screenshots for user-interface changes when useful.

## Security issues

Do not open a public issue for an exploitable vulnerability. Follow [SECURITY.md](SECURITY.md).
