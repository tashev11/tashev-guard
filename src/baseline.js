import fs from "node:fs/promises";
import path from "node:path";

const runtimeDir = path.resolve(process.env.TASHEV_GUARD_DATA_DIR || ".runtime");
const baselineFile = path.join(runtimeDir, "baseline.json");

function listenerKey(item) {
  return [item.process || "unknown", item.localPort || "", item.local || item.endpoint || ""].join("|");
}

function autorunKey(item) {
  return item.path || [item.scope || "", item.name || ""].join("|");
}

export function fingerprint(snapshot) {
  return {
    listeners: (snapshot.listening || []).map(listenerKey).sort(),
    autoruns: (snapshot.autoruns || []).map(autorunKey).sort(),
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
    version: 1,
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
    };
  }

  const current = fingerprint(snapshot);
  const listenerSet = new Set(baseline.listeners || []);
  const autorunSet = new Set(baseline.autoruns || []);
  const currentListenerSet = new Set(current.listeners);
  const currentAutorunSet = new Set(current.autoruns);

  return {
    ready: true,
    createdAt: baseline.createdAt,
    newListeners: (snapshot.listening || []).filter((x) => !listenerSet.has(listenerKey(x))),
    newAutoruns: (snapshot.autoruns || []).filter((x) => !autorunSet.has(autorunKey(x))),
    removedListeners: (baseline.listeners || []).filter((x) => !currentListenerSet.has(x)),
    removedAutoruns: (baseline.autoruns || []).filter((x) => !currentAutorunSet.has(x)),
  };
}
