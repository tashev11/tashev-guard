import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { collectSystem } from "./collectors/index.js";
import { readBaseline, saveBaseline, compareBaseline } from "./baseline.js";
import { assess, eventKey } from "./risk.js";
import { notifyCommand } from "./notify-command.js";

// Headless single-run mode for servers and cron. Importing this module runs
// nothing; src/watch-cli.js is the entry point.

export const MAX_NOTIFIED_KEYS = 2000;
export const MAX_MESSAGE_LENGTH = 3500;
const MAX_ALERT_LINE = 500;
const FIRST_LOOKBACK_MS = 65 * 60 * 1000;
// Re-read a little before the previous run: late log lines are not lost, and
// logins seen twice are deduplicated by their event keys.
const SINCE_OVERLAP_MS = 2 * 60 * 1000;
const MAX_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000;
const ALERT_LEVELS = new Set(["high", "medium"]);
const LEVEL_RANK = { high: 0, medium: 1, low: 2 };

export function parseTrustedKeys(value) {
  return [...new Set(String(value ?? "").split(/[\s,]+/).filter(Boolean))];
}

// High and medium findings that were not reported yet, each event once.
export function selectNewAlerts(findings = [], notifiedKeys = []) {
  const known = new Set(notifiedKeys);
  const alerts = [];
  for (const finding of findings) {
    if (!ALERT_LEVELS.has(finding.level)) continue;
    const key = eventKey(finding);
    if (known.has(key)) continue;
    known.add(key);
    alerts.push(finding);
  }
  return alerts;
}

function oneLine(value) {
  return String(value ?? "").replace(/\s*[\r\n]+\s*/g, " ").trim();
}

function alertLine(alert) {
  const detail = oneLine(alert.detail);
  const line = "[" + String(alert.level ?? "info").toUpperCase() + "] " + oneLine(alert.title) +
    (detail ? " — " + detail : "");
  return line.length > MAX_ALERT_LINE ? line.slice(0, MAX_ALERT_LINE - 1) + "…" : line;
}

// Plain text: a host header, then one line per alert, high first, at most
// MAX_MESSAGE_LENGTH characters ("… и ещё N" counts what did not fit).
export function formatAlert(hostname, alerts = []) {
  const rank = (alert) => LEVEL_RANK[alert.level] ?? 3;
  const lines = alerts
    .map((alert, index) => ({ alert, index }))
    .sort((a, b) => rank(a.alert) - rank(b.alert) || a.index - b.index)
    .map(({ alert }) => alertLine(alert));

  let text = "Tashev Guard · " + hostname;
  for (let i = 0; i < lines.length; i += 1) {
    const after = lines.length - i - 1;
    const next = text + "\n" + lines[i];
    const reserve = after > 0 ? ("\n… и ещё " + after).length : 0;
    if (next.length + reserve > MAX_MESSAGE_LENGTH) return text + "\n… и ещё " + (lines.length - i);
    text = next;
  }
  return text;
}

function uniqueCount(list) {
  return new Set(list ?? []).size;
}

function baselineCounts(baseline) {
  return "портов " + uniqueCount(baseline.listeners) +
    ", автозапуска " + uniqueCount(baseline.autoruns) +
    ", SSH-ключей " + uniqueCount(baseline.accessKeys) +
    ", учёток " + uniqueCount(baseline.accounts);
}

export function formatFirstRunSummary(hostname, baseline) {
  return "Tashev Guard на " + hostname + " включён. Эталон создан: " + baselineCounts(baseline) +
    ". Буду сообщать только об изменениях.";
}

export function formatResetSummary(hostname, baseline) {
  return "Tashev Guard на " + hostname + ": эталон переобучен: " + baselineCounts(baseline) +
    ". Уведомление не отправлялось.";
}

export function computeSince(lastRunAt, now) {
  const nowMs = now.getTime();
  const last = Date.parse(lastRunAt ?? "");
  if (Number.isNaN(last) || last > nowMs) return new Date(nowMs - FIRST_LOOKBACK_MS);
  return new Date(Math.max(last - SINCE_OVERLAP_MS, nowMs - MAX_LOOKBACK_MS));
}

// Keys of findings that are still present move to the end, so the cap only
// drops keys of events that are gone (old logins), never a standing finding.
export function mergeNotifiedKeys(previous = [], activeKeys = [], newKeys = [], limit = MAX_NOTIFIED_KEYS) {
  const active = new Set(activeKeys);
  const ordered = new Set(previous);
  for (const key of previous) {
    if (!active.has(key)) continue;
    ordered.delete(key);
    ordered.add(key);
  }
  for (const key of newKeys) {
    ordered.delete(key);
    ordered.add(key);
  }
  return [...ordered].slice(-limit);
}

async function loadState(file, log) {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8"));
    return {
      lastRunAt: typeof parsed?.lastRunAt === "string" ? parsed.lastRunAt : null,
      notifiedKeys: Array.isArray(parsed?.notifiedKeys)
        ? parsed.notifiedKeys.filter((key) => typeof key === "string")
        : [],
    };
  } catch (error) {
    if (error.code !== "ENOENT") {
      log("Tashev Guard: " + file + " не прочитан (" + (error.code || error.name) + "), начинаю с пустого состояния");
    }
    return { lastRunAt: null, notifiedKeys: [] };
  }
}

async function saveState(file, state) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temp = file + "." + process.pid + ".tmp";
  await fs.writeFile(temp, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  await fs.rename(temp, file);
}

function describeFailure(result) {
  if (result?.error) return String(result.error);
  if (result?.signal) return "сигнал " + result.signal;
  if (result?.code !== undefined && result?.code !== null) return "код " + result.code;
  return "нет ответа";
}

// One headless check. Every dependency can be replaced (tests); defaults are
// the real collectors, baseline files and TASHEV_GUARD_NOTIFY_CMD delivery.
// Returns the process exit code (0 unless something throws).
export async function runWatch(deps = {}) {
  const env = deps.env ?? process.env;
  const argv = deps.argv ?? [];
  const log = deps.log ?? ((line) => console.log(line));
  const now = deps.now ?? (() => new Date());
  const hostname = deps.hostname ?? os.hostname();
  const collect = deps.collect ?? collectSystem;
  const loadBaseline = deps.readBaseline ?? readBaseline;
  const storeBaseline = deps.saveBaseline ?? saveBaseline;
  const notify = deps.notify ?? ((message) => notifyCommand(message, { env }));
  const stateFile = path.join(path.resolve(deps.dataDir || env.TASHEV_GUARD_DATA_DIR || ".runtime"), "state.json");

  const startedAt = now();
  const stamp = "[" + startedAt.toISOString() + "] ";
  const state = await loadState(stateFile, log);
  const snapshot = await collect({ since: computeSince(state.lastRunAt, startedAt) });
  const warnings = snapshot.collectorWarnings ?? [];
  const logWarnings = () => {
    if (warnings.length) log(stamp + "Ограничения сбора: " + warnings.join("; "));
  };

  if (argv.includes("--reset-baseline")) {
    const baseline = await storeBaseline(snapshot);
    log(stamp + formatResetSummary(hostname, baseline));
    logWarnings();
    return 0;
  }

  let baseline = await loadBaseline();
  const firstRun = !baseline;
  if (firstRun) baseline = await storeBaseline(snapshot);

  const changes = compareBaseline(snapshot, baseline);
  const risk = assess(snapshot, changes, { trustedKeys: parseTrustedKeys(env.TASHEV_GUARD_TRUSTED_KEYS) });
  const activeKeys = risk.findings.filter((finding) => ALERT_LEVELS.has(finding.level)).map(eventKey);

  let message = null;
  let reportedKeys = [];
  if (firstRun) {
    // One summary instead of alerts; standing findings (e.g. the open SSH
    // port) count as reported so they do not fire on the next run.
    message = formatFirstRunSummary(hostname, baseline);
    reportedKeys = activeKeys;
  } else {
    const alerts = selectNewAlerts(risk.findings, state.notifiedKeys);
    if (alerts.length) {
      message = formatAlert(hostname, alerts);
      reportedKeys = alerts.map(eventKey);
    }
  }

  let delivered = true;
  if (message) {
    log(stamp + message);
    const result = await notify(message);
    delivered = Boolean(result?.ok);
    if (!delivered) {
      log(stamp + "Tashev Guard: уведомление не отправлено (" + describeFailure(result) + "), повторю при следующем запуске");
    }
  } else {
    log(stamp + "Tashev Guard: изменений нет");
  }
  logWarnings();

  // An undelivered alert keeps its keys unreported and the login window open,
  // so the next run sends it again. The first run never alerts on logins, so
  // its window always closes.
  await saveState(stateFile, {
    lastRunAt: delivered || firstRun ? startedAt.toISOString() : state.lastRunAt,
    notifiedKeys: mergeNotifiedKeys(state.notifiedKeys, activeKeys, delivered ? reportedKeys : []),
  });
  return 0;
}
