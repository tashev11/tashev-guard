import fs from "node:fs/promises";
import path from "node:path";

const runtimeDir = path.resolve(process.env.TASHEV_GUARD_DATA_DIR || ".runtime");
const baselineFile = path.join(runtimeDir, "baseline.json");

function listenerKey(item) {
  return [item.process || "unknown", item.localPort || "", item.local || item.endpoint || ""].join("|");
}

// Collectors that hash file contents (Linux) get "path#hash", so an edit of an
// existing file shows up as a change; macOS/Windows keys stay as before.
function autorunKey(item) {
  const key = item.path || [item.scope || "", item.name || ""].join("|");
  return item.hash ? key + "#" + item.hash : key;
}

function accessKeyKey(item) {
  return [item.user || "", item.fingerprint || ""].join("|");
}

function accountKey(item) {
  return [item.user || "", item.uid ?? "", item.shell ?? ""].join("|");
}

export function fingerprint(snapshot) {
  return {
    listeners: (snapshot.listening || []).map(listenerKey).sort(),
    autoruns: (snapshot.autoruns || []).map(autorunKey).sort(),
    accessKeys: (snapshot.accessKeys || []).map(accessKeyKey).sort(),
    accounts: (snapshot.accounts || []).map(accountKey).sort(),
  };
}

// A baseline saved before a category existed has no array for it: that
// category is "not learned yet" and must not turn every item into an alarm.
function diffLearned(items, keyOf, learned) {
  if (!Array.isArray(learned)) return { added: [], removed: [] };
  const known = new Set(learned);
  const current = new Set(items.map(keyOf));
  return {
    added: items.filter((item) => !known.has(keyOf(item))),
    removed: learned.filter((key) => !current.has(key)),
  };
}

export async function readBaseline() {
  try {
    return JSON.parse(await fs.readFile(baselineFile, "utf8"));
  } catch {
    return null;
  }
}

export async function saveBaseline(snapshot) {
  await fs.mkdir(runtimeDir, { recursive: true });
  const baseline = {
    version: 2,
    createdAt: new Date().toISOString(),
    ...fingerprint(snapshot),
  };
  await fs.writeFile(baselineFile, JSON.stringify(baseline, null, 2) + "\n");
  return baseline;
}

export async function removeBaseline() {
  await fs.rm(baselineFile, { force: true });
}

export function compareBaseline(snapshot, baseline) {
  if (!baseline) {
    return {
      ready: false,
      createdAt: null,
      newListeners: [],
      newAutoruns: [],
      removedListeners: [],
      removedAutoruns: [],
      newAccessKeys: [],
      removedAccessKeys: [],
      newAccounts: [],
      removedAccounts: [],
    };
  }

  const current = fingerprint(snapshot);
  const listenerSet = new Set(baseline.listeners || []);
  const autorunSet = new Set(baseline.autoruns || []);
  const currentListenerSet = new Set(current.listeners);
  const currentAutorunSet = new Set(current.autoruns);
  const accessKeys = diffLearned(snapshot.accessKeys || [], accessKeyKey, baseline.accessKeys);
  const accounts = diffLearned(snapshot.accounts || [], accountKey, baseline.accounts);

  return {
    ready: true,
    createdAt: baseline.createdAt,
    newListeners: (snapshot.listening || []).filter((x) => !listenerSet.has(listenerKey(x))),
    newAutoruns: (snapshot.autoruns || []).filter((x) => !autorunSet.has(autorunKey(x))),
    removedListeners: (baseline.listeners || []).filter((x) => !currentListenerSet.has(x)),
    removedAutoruns: (baseline.autoruns || []).filter((x) => !currentAutorunSet.has(x)),
    newAccessKeys: accessKeys.added,
    removedAccessKeys: accessKeys.removed,
    newAccounts: accounts.added,
    removedAccounts: accounts.removed,
  };
}
