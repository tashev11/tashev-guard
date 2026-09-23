import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { run } from "../command.js";

function decodeLsofValue(value) {
  if (!/\\x[0-9a-f]{2}/i.test(value)) return value;
  const binary = value.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
    String.fromCharCode(Number.parseInt(hex, 16))
  );
  return Buffer.from(binary, "latin1").toString("utf8");
}

export function parseLsof(text) {
  const rows = [];
  let current = {};
  for (const raw of text.split(/\r?\n/)) {
    if (!raw) continue;
    const tag = raw[0];
    const value = raw.slice(1);
    if (tag === "p") {
      if (current.pid && current.endpoint) rows.push(current);
      current = { pid: Number(value) || null };
    } else if (tag === "c") {
      current.process = decodeLsofValue(value);
    } else if (tag === "n") {
      if (current.pid && current.endpoint) rows.push(current);
      current = { ...current, endpoint: value };
    } else if (tag === "T" && value.startsWith("ST=")) {
      current.state = value.slice(3);
    }
  }
  if (current.pid && current.endpoint) rows.push(current);
  return rows;
}

function splitEndpoint(endpoint = "") {
  const arrow = endpoint.indexOf("->");
  const local = arrow >= 0 ? endpoint.slice(0, arrow) : endpoint;
  const remote = arrow >= 0 ? endpoint.slice(arrow + 2) : null;
  const portMatch = local.match(/:(\d+)$/);
  return { local, remote, localPort: portMatch ? Number(portMatch[1]) : null };
}

function parseWho(text) {
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    const remoteMatch = line.match(/\(([^)]+)\)\s*$/);
    const parts = line.trim().split(/\s+/);
    return {
      user: parts[0] ?? "unknown",
      terminal: parts[1] ?? "",
      remoteHost: remoteMatch?.[1] ?? null,
      raw: line.trim(),
    };
  }).filter((s) => s.remoteHost && s.remoteHost !== "console");
}

async function collectAutoruns() {
  const roots = [
    { scope: "user", dir: path.join(os.homedir(), "Library/LaunchAgents") },
    { scope: "system-agent", dir: "/Library/LaunchAgents" },
    { scope: "system-daemon", dir: "/Library/LaunchDaemons" },
  ];
  const rows = [];
  for (const root of roots) {
    try {
      const names = await fs.readdir(root.dir);
      for (const name of names.filter((x) => x.endsWith(".plist"))) {
        rows.push({ scope: root.scope, name, path: path.join(root.dir, name) });
      }
    } catch {}
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path));
}

function parseProcessLine(line) {
  const match = line.trim().match(/^(\d+)\s+(\S+)\s+(.*)$/);
  return match
    ? { pid: Number(match[1]), executable: match[2], process: path.basename(match[2]), command: match[3] }
    : { raw: line.trim() };
}

async function signatureFor(executable) {
  if (!executable || !executable.startsWith("/")) return null;
  const result = await run("codesign", ["-dv", "--verbose=2", executable]);
  const text = [result.stdout, result.stderr].join("\n");
  const pick = (key) => text.match(new RegExp("^" + key + "=(.+)$", "m"))?.[1] ?? null;
  return {
    signed: /Identifier=|Authority=|TeamIdentifier=/.test(text),
    identifier: pick("Identifier"),
    teamIdentifier: pick("TeamIdentifier"),
    authority: text.match(/^Authority=(.+)$/m)?.[1] ?? null,
  };
}

export async function collectMacOS() {
  const [lsof, who, ps, autoruns] = await Promise.all([
    run("lsof", ["-nP", "-FpcnT", "-iTCP"]),
    run("who"),
    run("ps", ["-axo", "pid=,comm=,args="]),
    collectAutoruns(),
  ]);

  const sockets = parseLsof(lsof.stdout).map((row) => ({ ...row, ...splitEndpoint(row.endpoint) }));
  const listening = sockets.filter((s) => s.state === "LISTEN");
  const connections = sockets.filter((s) => s.state === "ESTABLISHED" && s.remote);
  const remoteSessions = parseWho(who.stdout);
  const remotePattern = /(AnyDesk|TeamViewer|RustDesk|Screen Sharing|screensharingd|sshd|VNC|Chrome Remote Desktop)/i;
  const rawRemoteTools = ps.stdout.split(/\r?\n/).filter((line) => remotePattern.test(line)).map(parseProcessLine);
  const remoteTools = await Promise.all(rawRemoteTools.slice(0, 20).map(async (tool) => ({
    ...tool,
    signature: await signatureFor(tool.executable),
  })));

  return {
    platform: "macos",
    connections,
    listening,
    remoteSessions,
    remoteTools,
    autoruns,
    collectorWarnings: [
      ...(lsof.ok ? [] : ["lsof unavailable: network visibility is limited"]),
      ...(who.ok ? [] : ["who unavailable: session visibility is limited"]),
    ],
  };
}
