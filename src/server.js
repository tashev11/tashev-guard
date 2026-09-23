import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collectSystem } from "./collectors/index.js";
import { assess, eventKey } from "./risk.js";
import { appendEvents, readEvents } from "./store.js";
import { readBaseline, saveBaseline, removeBaseline, compareBaseline } from "./baseline.js";
import { notifyFinding } from "./notifier.js";
import { enrichConnections } from "./enrich.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, "../web");
const port = Number(process.env.PORT || 4782);
const host = "127.0.0.1";

let state = {
  generatedAt: null,
  snapshot: {
    connections: [],
    listening: [],
    remoteSessions: [],
    remoteTools: [],
    autoruns: [],
    collectorWarnings: [],
  },
  baseline: {
    ready: false,
    createdAt: null,
    justCreated: false,
    newListeners: 0,
    newAutoruns: 0,
    removedListeners: 0,
    removedAutoruns: 0,
  },
  risk: {
    status: "ok",
    findings: [],
    counts: { high: 0, medium: 0, low: 0, total: 0 },
  },
};

let previousKeys = new Set();
let firstScan = true;
let scanPromise = null;

function json(res, value, code = 200) {
  const body = JSON.stringify(value);
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}

function baselineSummary(changes, justCreated = false) {
  return {
    ready: changes.ready,
    createdAt: changes.createdAt,
    justCreated,
    newListeners: changes.newListeners.length,
    newAutoruns: changes.newAutoruns.length,
    removedListeners: changes.removedListeners.length,
    removedAutoruns: changes.removedAutoruns.length,
  };
}

async function scan() {
  if (scanPromise) return scanPromise;

  scanPromise = (async () => {
    const snapshot = await collectSystem();
    snapshot.connections = await enrichConnections(snapshot.connections);

    let baseline = await readBaseline();
    let justCreated = false;
    if (!baseline) {
      baseline = await saveBaseline(snapshot);
      justCreated = true;
    }

    const baselineChanges = compareBaseline(snapshot, baseline);
    const risk = assess(snapshot, baselineChanges);
    const now = new Date().toISOString();
    const keys = new Set(risk.findings.map(eventKey));

    let fresh = [];
    if (!justCreated) {
      fresh = firstScan
        ? risk.findings
        : risk.findings.filter((finding) => !previousKeys.has(eventKey(finding)));
    }

    if (fresh.length) {
      const events = fresh.map((finding) => ({ ...finding, detectedAt: now }));
      await appendEvents(events);
      for (const finding of fresh.filter((x) => x.level !== "low")) {
        await notifyFinding(finding).catch(() => {});
      }
    }

    previousKeys = keys;
    firstScan = false;
    state = {
      generatedAt: now,
      snapshot,
      baseline: baselineSummary(baselineChanges, justCreated),
      risk,
    };
    return state;
  })();

  try {
    return await scanPromise;
  } finally {
    scanPromise = null;
  }
}

async function serveStatic(req, res) {
  const pathname = new URL(req.url, "http://" + host).pathname;
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const safe = relative.split("/").filter((part) => part && part !== "." && part !== "..").join("/");
  const file = path.join(webRoot, safe);

  if (!file.startsWith(webRoot)) {
    return json(res, { error: "not found" }, 404);
  }

  try {
    const body = await fs.readFile(file);
    const ext = path.extname(file);
    const types = {
      ".html": "text/html",
      ".js": "text/javascript",
      ".css": "text/css",
      ".svg": "image/svg+xml",
    };
    res.writeHead(200, {
      "content-type": (types[ext] || "application/octet-stream") + "; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:;",
      "x-content-type-options": "nosniff",
    });
    res.end(body);
  } catch {
    json(res, { error: "not found" }, 404);
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url?.startsWith("/api/baseline/reset")) {
      if (req.headers["x-tashev-guard"] !== "1") {
        return json(res, { error: "forbidden" }, 403);
      }
      await removeBaseline();
      previousKeys = new Set();
      firstScan = true;
      return json(res, await scan());
    }

    if (req.method !== "GET") {
      return json(res, { error: "method not allowed" }, 405);
    }
    if (req.url?.startsWith("/api/status")) {
      return json(res, await scan());
    }
    if (req.url?.startsWith("/api/events")) {
      return json(res, await readEvents(100));
    }
    if (req.url?.startsWith("/api/health")) {
      return json(res, { ok: true, service: "tashev-guard", port });
    }
    return serveStatic(req, res);
  } catch (error) {
    return json(res, { error: error.message }, 500);
  }
});

server.listen(port, host, async () => {
  await scan().catch(() => {});
  console.log("Tashev Guard: http://" + host + ":" + port);
  console.log("Local-only mode: dashboard is bound to 127.0.0.1.");
});

setInterval(() => scan().catch(() => {}), 5000).unref();
