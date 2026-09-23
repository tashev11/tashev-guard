# Privacy Notes

Tashev Guard is local-first.

Current preview behavior:

- desktop monitoring data is collected on the device;
- the dashboard is served from `127.0.0.1`;
- local history stays in the local runtime directory;
- no Tashev Guard cloud account is required;
- no project telemetry is sent by the application;
- Android audit results remain on the phone unless the user explicitly shares the report;
- normal DNS lookups may of course be visible to the DNS resolver configured on the device.

Future hosted or multi-device features must be opt-in and documented separately before release.
