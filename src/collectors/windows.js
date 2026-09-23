import { run } from "../command.js";

function normalizeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function parseJson(text) {
  try { return normalizeArray(JSON.parse(text || "[]")); }
  catch { return []; }
}

export async function collectWindows() {
  const tcpScript = [
    "$ErrorActionPreference='SilentlyContinue'",
    "$tcp=Get-NetTCPConnection | Where-Object {$_.State -in @('Listen','Established')}",
    "$rows=@(); foreach($c in $tcp){",
    "  $p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue",
    "  $rows += [pscustomobject]@{pid=$c.OwningProcess;process=$p.ProcessName;state=$c.State;local=($c.LocalAddress+':'+$c.LocalPort);remote=if($c.State -eq 'Established'){($c.RemoteAddress+':'+$c.RemotePort)}else{$null};localPort=$c.LocalPort}",
    "}",
    "$rows | ConvertTo-Json -Compress",
  ].join(";");

  const [tcp, sessionsRaw, toolsRaw, autorunsRaw] = await Promise.all([
    run("powershell.exe", ["-NoProfile", "-Command", tcpScript]),
    run("quser.exe"),
    run("powershell.exe", ["-NoProfile", "-Command",
      "$p=Get-Process | Where-Object {$_.ProcessName -match 'AnyDesk|TeamViewer|RustDesk|vnc|remoting'}; $p | ForEach-Object {$sig=if($_.Path){Get-AuthenticodeSignature $_.Path}else{$null}; [pscustomobject]@{pid=$_.Id;process=$_.ProcessName;command=$_.Path;signed=($sig.Status -eq 'Valid');signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null}}} | ConvertTo-Json -Compress"
    ]),
    run("powershell.exe", ["-NoProfile", "-Command",
      "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress"
    ]),
  ]);

  const rows = parseJson(tcp.stdout);
  const remoteSessions = sessionsRaw.ok
    ? sessionsRaw.stdout.split(/\r?\n/).slice(1).filter(Boolean).map((raw) => ({ raw: raw.trim() }))
    : [];
  const remoteTools = parseJson(toolsRaw.stdout).map((p) => ({
    pid: p.pid,
    process: p.process,
    command: p.command ?? "",
    signature: { signed: Boolean(p.signed), authority: p.signer ?? null },
  }));
  const autoruns = parseJson(autorunsRaw.stdout).map((item) => ({
    scope: "startup",
    name: item.Name ?? "unknown",
    path: [item.Location, item.Name, item.Command].filter(Boolean).join(" | "),
    command: item.Command ?? "",
    user: item.User ?? null,
  }));

  return {
    platform: "windows",
    connections: rows.filter((r) => r.state === "Established"),
    listening: rows.filter((r) => r.state === "Listen"),
    remoteSessions,
    remoteTools,
    autoruns,
    collectorWarnings: [
      ...(tcp.ok ? [] : ["Get-NetTCPConnection unavailable: network visibility is limited"]),
      ...(autorunsRaw.ok ? [] : ["Startup command inventory unavailable"]),
    ],
  };
}
