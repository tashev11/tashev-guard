import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { run as defaultRun } from "../command.js";
import { parseWho } from "./who.js";

const SS_STATES = new Map([
  ["LISTEN", "LISTEN"],
  ["ESTAB", "ESTABLISHED"],
]);

// sshd is deliberately absent: servers always run it, and port 22 is already
// reported as a remote-access port finding.
export const LINUX_REMOTE_TOOL_PATTERN =
  /(AnyDesk|TeamViewer|RustDesk|x11vnc|Xvnc|vncserver|tigervnc|ngrok|frpc|chisel|gost|cloudflared|tailscaled|zerotier-one|teleport|ligolo)/i;

const NON_LOGIN_SHELL = /(?:^|\/)(?:nologin|false|sync|halt|shutdown)$/;
const SECRET_ARGUMENT = /(--?(?:token|auth(?:-?key|token)?|password|passwd|pass|secret)(?:=|\s+))\S+/gi;
const SYSTEMD_UNIT = /\.(?:service|timer|socket|path)$/;
const PACKAGE_UNIT_PREFIXES = ["/lib/", "/usr/lib/"];
const CRON_DIRS = [
  "/etc/cron.d",
  "/etc/cron.hourly",
  "/etc/cron.daily",
  "/etc/cron.weekly",
  "/etc/cron.monthly",
  "/var/spool/cron/crontabs",
  "/var/spool/cron",
];
const AUTH_LOG_FILES = ["/var/log/auth.log", "/var/log/secure"];
const AUTH_LOG_TAIL_BYTES = 16 * 1024 * 1024;
const DEFAULT_LOGIN_WINDOW_MS = 65 * 60 * 1000;
const MAX_REMOTE_TOOLS = 20;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/;
const SYSLOG_TIMESTAMP = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/;
// "<timestamp> <host> <ident>[<pid>]: Accepted <method> for <user> from <ip> port <port> ssh2[: <type> <fp>]"
// "Accepted" must follow the ident directly, so text injected through a
// username in other sshd messages cannot fake a login.
const ACCEPTED_LINE =
  /^(\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+[\w.@\/-]+\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)(?:\s+ssh2)?(?::\s+(\S+)\s+(\S+))?/;
const KEYGEN_LINE = /^(\d+)\s+(\S+)(?:\s+(.*?))?\s+\(([^()]+)\)\s*$/;

function errorCode(error) {
  return error?.code || error?.message || "error";
}

function toDate(value) {
  if (value === undefined || value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function shortHash(content) {
  return crypto.createHash("sha256").update(content).digest("hex").slice(0, 16);
}

function portOf(address = "") {
  const match = address.match(/:(\d+)$/);
  return match ? Number(match[1]) : null;
}

// `ss -H -tanp` rows: State Recv-Q Send-Q Local:Port Peer:Port [users:((...))]
export function parseSs(text) {
  const rows = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const usersAt = line.indexOf("users:(");
    const columns = (usersAt >= 0 ? line.slice(0, usersAt) : line).trim().split(/\s+/);
    if (!SS_STATES.has(columns[0]) && SS_STATES.has(columns[1])) columns.shift(); // Netid column
    const state = SS_STATES.get(columns[0]);
    if (!state || columns.length < 5) continue;

    const local = columns[3];
    const remote = state === "ESTABLISHED" ? columns[4] : null;
    const owner = usersAt >= 0 ? line.slice(usersAt).match(/^users:\(\("(.*?)",pid=(\d+)/) : null;
    rows.push({
      state,
      local,
      remote,
      localPort: portOf(local),
      pid: owner ? Number(owner[2]) : null,
      process: owner ? owner[1] : null,
      endpoint: remote ? local + "->" + remote : local,
    });
  }
  return rows;
}

function redactSecrets(command) {
  return command.replace(SECRET_ARGUMENT, "$1***");
}

// `ps -eo pid=,comm=,args=` rows matching the Linux remote-access pattern.
export function parseRemoteTools(text) {
  const tools = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    if (!LINUX_REMOTE_TOOL_PATTERN.test(line)) continue;
    const match = line.match(/^\s*(\d+)\s+(\S+)\s+(.*)$/);
    if (!match) continue;
    const command = redactSecrets(match[3].trim());
    tools.push({
      pid: Number(match[1]),
      process: match[2],
      executable: command.split(/\s+/)[0] || null,
      command,
      signature: null,
    });
  }
  return tools;
}

// `ssh-keygen -lf <file>` lines: "<bits> <fingerprint> <comment...> (<TYPE>)".
// Only fingerprints, comments and types are kept, never key material.
export function parseKeygenList(text, user, file) {
  const keys = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const match = raw.trim().match(KEYGEN_LINE);
    if (!match) continue;
    keys.push({
      user,
      file,
      bits: Number(match[1]),
      fingerprint: match[2],
      comment: (match[3] ?? "").trim(),
      type: match[4],
    });
  }
  return keys;
}

function parsePasswdEntries(text) {
  const entries = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("+") || line.startsWith("-")) continue;
    const fields = line.split(":");
    if (fields.length < 7 || !fields[0] || !/^\d+$/.test(fields[2])) continue;
    entries.push({ user: fields[0], uid: Number(fields[2]), home: fields[5], shell: fields[6].trim() });
  }
  return entries;
}

function isLoginAccount(entry) {
  // An empty shell field means /bin/sh, so it counts as a login shell.
  return entry.uid === 0 || !NON_LOGIN_SHELL.test(entry.shell);
}

// Accounts that can log in (any shell except nologin/false/sync/halt/shutdown) plus every uid 0 account.
export function parsePasswd(text) {
  return parsePasswdEntries(text)
    .filter(isLoginAccount)
    .map(({ user, uid, shell }) => ({ user, uid, shell }));
}

function normalizeMethod(method) {
  return method.toLowerCase().split("/")[0];
}

function normalizeLogTime(stamp, now) {
  if (ISO_TIMESTAMP.test(stamp)) {
    const ms = Date.parse(stamp.replace(",", "."));
    return Number.isNaN(ms) ? stamp : new Date(ms).toISOString();
  }
  const match = stamp.match(SYSLOG_TIMESTAMP);
  const month = match ? MONTHS.indexOf(match[1]) : -1;
  if (month < 0) return stamp;
  const [day, hour, minute, second] = match.slice(2).map(Number);
  // Classic syslog lines carry no year: take the current one, or the previous
  // one when that would put the line in the future (December lines in January).
  let date = new Date(now.getFullYear(), month, day, hour, minute, second);
  if (date.getTime() - now.getTime() > 24 * 60 * 60 * 1000) {
    date = new Date(now.getFullYear() - 1, month, day, hour, minute, second);
  }
  return date.toISOString();
}

// Successful SSH logins from journalctl (-o short-iso) or auth.log text.
export function parseSshAccepted(text, options = {}) {
  const now = toDate(options.now) ?? new Date();
  const logins = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const match = raw.trim().match(ACCEPTED_LINE);
    if (!match) continue;
    const [, stamp, rawMethod, user, ip, port, keyType, fingerprint] = match;
    const method = normalizeMethod(rawMethod);
    const byKey = method === "publickey";
    logins.push({
      time: normalizeLogTime(stamp, now),
      user,
      method,
      ip,
      port: Number(port),
      keyType: byKey && keyType ? keyType : null,
      fingerprint: byKey && fingerprint ? fingerprint : null,
    });
  }
  return logins;
}

function createContext(root) {
  const base = path.resolve(root || "/");
  const warnings = [];
  return {
    warnings,
    abs: (logical) => (base === "/" ? logical : path.join(base, logical)),
    warn: (message) => {
      if (!warnings.includes(message)) warnings.push(message);
    },
  };
}

async function listDir(ctx, logicalDir) {
  try {
    return await fs.readdir(ctx.abs(logicalDir), { withFileTypes: true });
  } catch (error) {
    if (error.code !== "ENOENT" && error.code !== "ENOTDIR") {
      ctx.warn("cannot list " + logicalDir + " (" + errorCode(error) + ")");
    }
    return [];
  }
}

async function hashFile(ctx, logicalPath) {
  try {
    return shortHash(await fs.readFile(ctx.abs(logicalPath)));
  } catch (error) {
    ctx.warn("cannot read " + logicalPath + " (" + errorCode(error) + ")");
    return null;
  }
}

async function fileAutorun(ctx, scope, name, logicalPath, { nonEmpty = false } = {}) {
  let stat;
  try {
    stat = await fs.stat(ctx.abs(logicalPath));
  } catch (error) {
    if (error.code !== "ENOENT" && error.code !== "ENOTDIR") {
      ctx.warn("cannot check " + logicalPath + " (" + errorCode(error) + ")");
    }
    return [];
  }
  if (!stat.isFile() || (nonEmpty && stat.size === 0)) return [];
  return [{ scope, name, path: logicalPath, hash: await hashFile(ctx, logicalPath) }];
}

async function dirFileAutoruns(ctx, scope, logicalDir) {
  const label = path.posix.basename(logicalDir);
  const rows = [];
  for (const entry of await listDir(ctx, logicalDir)) {
    if (entry.isDirectory()) continue;
    rows.push(...await fileAutorun(ctx, scope, label + "/" + entry.name, path.posix.join(logicalDir, entry.name)));
  }
  return rows;
}

async function systemdEntry(ctx, entry, logicalDir, name) {
  const logicalPath = path.posix.join(logicalDir, entry.name);
  if (!entry.isSymbolicLink()) {
    return entry.isFile() ? [{ scope: "systemd", name, path: logicalPath, hash: await hashFile(ctx, logicalPath) }] : [];
  }

  let target;
  try {
    target = path.posix.resolve(logicalDir, await fs.readlink(ctx.abs(logicalPath)));
  } catch (error) {
    ctx.warn("cannot read link " + logicalPath + " (" + errorCode(error) + ")");
    return [];
  }
  // Package units enabled or aliased from /lib or /usr/lib are not admin persistence.
  if (PACKAGE_UNIT_PREFIXES.some((prefix) => target.startsWith(prefix))) return [];
  if (target === "/dev/null") {
    return [{ scope: "systemd", name, path: logicalPath, hash: shortHash(""), target }];
  }

  let hash = null;
  try {
    if ((await fs.stat(ctx.abs(logicalPath))).isFile()) hash = await hashFile(ctx, logicalPath);
  } catch (error) {
    if (error.code !== "ENOENT") ctx.warn("cannot check " + logicalPath + " (" + errorCode(error) + ")");
  }
  return [{ scope: "systemd", name, path: logicalPath, hash, target }];
}

async function systemdDirAutoruns(ctx, logicalDir, namePrefix = "") {
  const rows = [];
  for (const entry of await listDir(ctx, logicalDir)) {
    if (entry.isDirectory() && entry.name.endsWith(".d")) {
      const dropInDir = path.posix.join(logicalDir, entry.name);
      for (const inner of await listDir(ctx, dropInDir)) {
        if (!inner.name.endsWith(".conf")) continue;
        rows.push(...await systemdEntry(ctx, inner, dropInDir, namePrefix + entry.name + "/" + inner.name));
      }
      continue;
    }
    if (SYSTEMD_UNIT.test(entry.name)) {
      rows.push(...await systemdEntry(ctx, entry, logicalDir, namePrefix + entry.name));
    }
  }
  return rows;
}

// Persistence inventory: systemd units and drop-ins, cron, boot hooks, sudoers.
// `hash` (first 16 hex chars of sha256) makes edits of an existing file visible.
// `root` exists for tests; production always scans "/".
export async function collectLinuxAutoruns(options = {}) {
  const ctx = options.context ?? createContext(options.root);
  const groups = await Promise.all([
    systemdDirAutoruns(ctx, "/etc/systemd/system"),
    systemdDirAutoruns(ctx, "/root/.config/systemd/user", "user/"),
    fileAutorun(ctx, "cron", "crontab", "/etc/crontab"),
    ...CRON_DIRS.map((dir) => dirFileAutoruns(ctx, "cron", dir)),
    fileAutorun(ctx, "boot", "rc.local", "/etc/rc.local", { nonEmpty: true }),
    fileAutorun(ctx, "boot", "ld.so.preload", "/etc/ld.so.preload", { nonEmpty: true }),
    fileAutorun(ctx, "sudoers", "sudoers", "/etc/sudoers"),
    dirFileAutoruns(ctx, "sudoers", "/etc/sudoers.d"),
  ]);
  return {
    autoruns: groups.flat().sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
    warnings: ctx.warnings,
  };
}

async function collectAccessKeys(ctx, run, entries) {
  const files = new Map();
  const addHome = (user, home) => {
    if (!home || !home.startsWith("/")) return;
    for (const name of ["authorized_keys", "authorized_keys2"]) {
      const file = path.posix.join(home, ".ssh", name);
      if (!files.has(file)) files.set(file, user);
    }
  };
  addHome("root", "/root");
  for (const entry of entries) addHome(entry.user, entry.home);

  const keys = [];
  for (const [file, user] of files) {
    let stat;
    try {
      stat = await fs.stat(ctx.abs(file));
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") {
        ctx.warn("cannot check " + file + " (" + errorCode(error) + ")");
      }
      continue;
    }
    if (!stat.isFile() || stat.size === 0) continue;

    const result = await run("ssh-keygen", ["-lf", ctx.abs(file)]);
    const parsed = parseKeygenList(result.stdout, user, file);
    if (!parsed.length && !result.ok) {
      if (result.code === "ENOENT") {
        ctx.warn("ssh-keygen unavailable: SSH key inventory is not visible");
        break;
      }
      ctx.warn("ssh-keygen could not read " + file);
    }
    keys.push(...parsed);
  }
  return keys;
}

async function readTail(file, maxBytes) {
  const handle = await fs.open(file, "r");
  try {
    const { size } = await handle.stat();
    const start = Math.max(0, size - maxBytes);
    const buffer = Buffer.alloc(size - start);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, start + offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const text = buffer.subarray(0, offset).toString("utf8");
    return start > 0 ? text.slice(text.indexOf("\n") + 1) : text;
  } finally {
    await handle.close();
  }
}

async function collectSshLogins(ctx, run, since, now) {
  const sinceMs = since.getTime();
  const inWindow = (login) => {
    const time = Date.parse(login.time);
    return Number.isNaN(time) || time >= sinceMs;
  };

  // OpenSSH >= 9.8 logs from the per-session binary "sshd-session".
  const journal = await run("journalctl", [
    "_COMM=sshd",
    "_COMM=sshd-session",
    "--since",
    "@" + Math.floor(sinceMs / 1000),
    "-o",
    "short-iso",
    "--no-pager",
  ], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 });
  if (journal.ok) return parseSshAccepted(journal.stdout, { now }).filter(inWindow);

  for (const file of AUTH_LOG_FILES) {
    let text;
    try {
      text = await readTail(ctx.abs(file), AUTH_LOG_TAIL_BYTES);
    } catch (error) {
      if (error.code !== "ENOENT") ctx.warn("cannot read " + file + " (" + errorCode(error) + ")");
      continue;
    }
    return parseSshAccepted(text, { now }).filter(inWindow);
  }
  ctx.warn("journalctl and " + AUTH_LOG_FILES.join(" / ") + " unavailable: SSH logins are not visible");
  return [];
}

async function readPasswd(ctx) {
  try {
    return await fs.readFile(ctx.abs("/etc/passwd"), "utf8");
  } catch (error) {
    ctx.warn("cannot read /etc/passwd (" + errorCode(error) + "): accounts and SSH keys are limited");
    return "";
  }
}

async function runSs(run) {
  const result = await run("ss", ["-H", "-tanp"]);
  if (result.ok || result.code === "ENOENT") return result;
  // iproute2 older than 4.13 has no -H; parseSs skips the header line itself.
  const legacy = await run("ss", ["-tanp"]);
  return legacy.ok ? legacy : result;
}

// options.since: Date or epoch ms (default: now - 65 min) for SSH logins.
// options.root / options.run / options.isRoot / options.now exist for tests.
export async function collectLinux(options = {}) {
  const run = options.run ?? defaultRun;
  const ctx = createContext(options.root);
  const now = toDate(options.now) ?? new Date();
  const since = toDate(options.since) ?? new Date(now.getTime() - DEFAULT_LOGIN_WINDOW_MS);
  const isRoot = options.isRoot ?? (typeof process.getuid === "function" && process.getuid() === 0);

  const [ss, who, ps, passwd, persistence, sshLogins] = await Promise.all([
    runSs(run),
    run("who"),
    run("ps", ["-eo", "pid=,comm=,args="]),
    readPasswd(ctx),
    collectLinuxAutoruns({ context: ctx }),
    collectSshLogins(ctx, run, since, now),
  ]);

  const loginEntries = parsePasswdEntries(passwd).filter(isLoginAccount);
  const accessKeys = await collectAccessKeys(ctx, run, loginEntries);
  const sockets = parseSs(ss.ok ? ss.stdout : "");

  return {
    platform: "linux",
    connections: sockets.filter((s) => s.state === "ESTABLISHED" && s.remote),
    listening: sockets.filter((s) => s.state === "LISTEN"),
    remoteSessions: parseWho(who.ok ? who.stdout : ""),
    remoteTools: parseRemoteTools(ps.ok ? ps.stdout : "").slice(0, MAX_REMOTE_TOOLS),
    autoruns: persistence.autoruns,
    accessKeys,
    accounts: loginEntries.map(({ user, uid, shell }) => ({ user, uid, shell })),
    sshLogins,
    collectorWarnings: [
      ...(isRoot ? [] : ["not running as root: other users' sockets, crontabs, sudoers and SSH logs may be incomplete"]),
      ...(ss.ok ? [] : ["ss unavailable: network visibility is limited"]),
      ...(who.ok ? [] : ["who unavailable: session visibility is limited"]),
      ...(ps.ok ? [] : ["ps unavailable: remote-tool visibility is limited"]),
      ...ctx.warnings,
    ],
  };
}
