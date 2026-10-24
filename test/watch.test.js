import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { selectNewAlerts, formatAlert, parseTrustedKeys, runWatch } from "../src/watch.js";
import { eventKey } from "../src/risk.js";
import { fingerprint } from "../src/baseline.js";

const HOUR = 60 * 60 * 1000;

function finding(level, title, detail, evidence = {}) {
  return { level, type: title, title, detail, evidence };
}

test("selectNewAlerts keeps new high and medium findings, each once", () => {
  const known = finding("medium", "Открыт порт удалённого доступа: SSH", "sshd · *:22", { pid: 1, local: "*:22" });
  const high = finding("high", "Добавлен новый SSH-ключ доступа", "root · SHA256:x", { fingerprint: "SHA256:x" });
  const medium = finding("medium", "Новый элемент автозапуска", "evil.service · systemd", { path: "/etc/systemd/system/evil.service", hash: "1" });
  const low = finding("low", "Вход по SSH", "root ← 1.2.3.4", { time: "t" });
  const alerts = selectNewAlerts([known, high, medium, low, { ...high }], [eventKey(known)]);
  assert.deepEqual(alerts, [high, medium]);
});

test("formatAlert puts the host header first and high alerts before medium ones", () => {
  const text = formatAlert("web-1", [
    finding("medium", "Запущен инструмент удалённого доступа", "frpc · PID 7"),
    finding("high", "Добавлен новый SSH-ключ доступа", "root · SHA256:x"),
    finding("medium", "Новый listening-порт после обучения", "nc · 0.0.0.0:4444"),
    finding("high", "Вход на сервер по паролю", "root ← 6.6.6.6\n· password"),
  ]);
  assert.equal(text, [
    "Tashev Guard · web-1",
    "[HIGH] Добавлен новый SSH-ключ доступа — root · SHA256:x",
    "[HIGH] Вход на сервер по паролю — root ← 6.6.6.6 · password",
    "[MEDIUM] Запущен инструмент удалённого доступа — frpc · PID 7",
    "[MEDIUM] Новый listening-порт после обучения — nc · 0.0.0.0:4444",
  ].join("\n"));
});

test("formatAlert stays within 3500 characters and counts the alerts it cut", () => {
  const alerts = Array.from({ length: 120 }, (_, index) =>
    finding(index % 2 ? "medium" : "high", "Новый элемент автозапуска", "unit-" + index + " · " + "x".repeat(60)));
  const text = formatAlert("web-1", alerts);
  assert.ok(text.length <= 3500, "length " + text.length);
  const lines = text.split("\n");
  assert.equal(lines[0], "Tashev Guard · web-1");
  const cut = lines.at(-1).match(/^… и ещё (\d+)$/);
  assert.ok(cut, lines.at(-1));
  const shown = lines.slice(1, -1);
  assert.equal(shown.length + Number(cut[1]), 120);
  assert.ok(shown.every((line) => line.startsWith("[HIGH]")), "high alerts must come first");
});

test("formatAlert shortens a single oversized alert", () => {
  const text = formatAlert("web-1", [finding("high", "Новый элемент автозапуска", "y".repeat(10000))]);
  assert.ok(text.length <= 3500, "length " + text.length);
  assert.match(text, /^Tashev Guard · web-1\n\[HIGH\] Новый элемент автозапуска — y+…$/);
});

test("parseTrustedKeys accepts comma, space and newline separated fingerprints", () => {
  assert.deepEqual(parseTrustedKeys(" SHA256:a, SHA256:b\nSHA256:c,,SHA256:a "), ["SHA256:a", "SHA256:b", "SHA256:c"]);
  assert.deepEqual(parseTrustedKeys(undefined), []);
});

const intruderKey = {
  user: "root", file: "/root/.ssh/authorized_keys", bits: 256,
  fingerprint: "SHA256:intruder", comment: "x", type: "ED25519",
};

function baseSnapshot() {
  return {
    platform: "linux",
    connections: [],
    listening: [
      { state: "LISTEN", local: "0.0.0.0:22", remote: null, localPort: 22, pid: 900, process: "sshd", endpoint: "0.0.0.0:22" },
      { state: "LISTEN", local: "0.0.0.0:443", remote: null, localPort: 443, pid: 1234, process: "nginx", endpoint: "0.0.0.0:443" },
    ],
    remoteSessions: [],
    remoteTools: [],
    autoruns: [{ scope: "cron", name: "crontab", path: "/etc/crontab", hash: "aaaaaaaaaaaaaaaa" }],
    accessKeys: [{ user: "root", file: "/root/.ssh/authorized_keys", bits: 256, fingerprint: "SHA256:owner", comment: "owner@laptop", type: "ED25519" }],
    accounts: [{ user: "root", uid: 0, shell: "/bin/bash" }],
    sshLogins: [],
    collectorWarnings: [],
  };
}

async function harness(t, { realNotify = false } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "tashev-guard-watch-"));
  t.after(() => fs.rm(dataDir, { recursive: true, force: true }));
  const stateFile = path.join(dataDir, "state.json");
  const h = {
    dataDir,
    snapshot: baseSnapshot(),
    clock: new Date("2026-10-24T10:07:00.000Z"),
    notifyResult: { ok: true },
    stored: null,
    saves: 0,
    sent: [],
    sinces: [],
    output: [],
    advance(ms) {
      h.clock = new Date(h.clock.getTime() + ms);
    },
    async readState() {
      return JSON.parse(await fs.readFile(stateFile, "utf8"));
    },
    async writeState(state) {
      await fs.writeFile(stateFile, JSON.stringify(state));
    },
    run(argv = []) {
      return runWatch({
        argv,
        env: { TASHEV_GUARD_TRUSTED_KEYS: "SHA256:owner" },
        dataDir,
        hostname: "web-1",
        now: () => h.clock,
        collect: async (options) => {
          h.sinces.push(options.since);
          return structuredClone(h.snapshot);
        },
        readBaseline: async () => h.stored,
        saveBaseline: async (snapshot) => {
          h.saves += 1;
          h.stored = { version: 2, createdAt: h.clock.toISOString(), ...fingerprint(snapshot) };
          return h.stored;
        },
        ...(realNotify ? {} : {
          notify: async (message) => {
            h.sent.push(message);
            return h.notifyResult;
          },
        }),
        log: (line) => h.output.push(line),
      });
    },
  };
  return h;
}

test("first run learns the baseline, sends one summary and marks current findings", async (t) => {
  const h = await harness(t);
  assert.equal(await h.run(), 0);
  assert.equal(h.saves, 1);
  assert.deepEqual(h.sent, [
    "Tashev Guard на web-1 включён. Эталон создан: портов 2, автозапуска 1, SSH-ключей 1, учёток 1. Буду сообщать только об изменениях.",
  ]);
  assert.equal(h.sinces[0].toISOString(), "2026-10-24T09:02:00.000Z");
  const state = await h.readState();
  assert.equal(state.lastRunAt, "2026-10-24T10:07:00.000Z");
  assert.equal(state.notifiedKeys.length, 1);
  assert.match(state.notifiedKeys[0], /remote-port/);
  assert.ok(h.output.some((line) => line.includes("включён")));
});

test("later runs without changes stay quiet and continue the login window", async (t) => {
  const h = await harness(t);
  await h.run();
  h.advance(HOUR);
  assert.equal(await h.run(), 0);
  assert.equal(h.sent.length, 1);
  assert.ok(h.output.some((line) => line.includes("Tashev Guard: изменений нет")));
  assert.equal(h.sinces[1].toISOString(), "2026-10-24T10:05:00.000Z");
  assert.equal((await h.readState()).lastRunAt, "2026-10-24T11:07:00.000Z");
});

test("new key, new sudoers file, new listener and password login are alerted once", async (t) => {
  const h = await harness(t);
  await h.run();
  h.advance(HOUR);
  h.snapshot.accessKeys.push(intruderKey);
  h.snapshot.autoruns.push({ scope: "sudoers", name: "sudoers.d/99-x", path: "/etc/sudoers.d/99-x", hash: "bbbbbbbbbbbbbbbb" });
  h.snapshot.listening.push({ state: "LISTEN", local: "0.0.0.0:4444", remote: null, localPort: 4444, pid: 66, process: "nc", endpoint: "0.0.0.0:4444" });
  h.snapshot.sshLogins.push(
    { time: "2026-10-24T10:30:00.000Z", user: "root", method: "password", ip: "6.6.6.6", port: 1, keyType: null, fingerprint: null },
    { time: "2026-10-24T10:31:00.000Z", user: "root", method: "publickey", ip: "1.2.3.4", port: 2, keyType: "ED25519", fingerprint: "SHA256:owner" },
    { time: "2026-10-24T10:32:00.000Z", user: "root", method: "publickey", ip: "6.6.6.7", port: 3, keyType: "RSA", fingerprint: "SHA256:stranger" },
  );
  await h.run();
  assert.equal(h.sent.length, 2);
  const lines = h.sent[1].split("\n");
  assert.equal(lines[0], "Tashev Guard · web-1");
  assert.deepEqual(lines.slice(1).map((line) => line.slice(0, line.indexOf(" — "))), [
    "[HIGH] Новый элемент автозапуска",
    "[HIGH] Добавлен новый SSH-ключ доступа",
    "[HIGH] Вход на сервер по паролю",
    "[HIGH] Вход по ключу не из доверенных",
    "[MEDIUM] Новый listening-порт после обучения",
  ]);
  assert.ok(!h.sent[1].includes("SHA256:owner"), "the trusted key login must stay silent");

  h.advance(HOUR);
  await h.run();
  assert.equal(h.sent.length, 2, "already reported findings must not repeat");
});

test("a failed notification is retried next run and keeps the login window open", async (t) => {
  const h = await harness(t);
  await h.run();
  h.advance(HOUR);
  h.snapshot.accessKeys.push(intruderKey);
  h.notifyResult = { ok: false, code: 1 };
  assert.equal(await h.run(), 0);
  let state = await h.readState();
  assert.equal(state.lastRunAt, "2026-10-24T10:07:00.000Z");
  assert.ok(!state.notifiedKeys.some((key) => key.includes("SHA256:intruder")));
  assert.ok(h.output.some((line) => line.includes("уведомление не отправлено")));

  h.advance(HOUR);
  h.notifyResult = { ok: true };
  await h.run();
  assert.equal(h.sent.length, 3);
  assert.equal(h.sent[2], h.sent[1]);
  assert.equal(h.sinces[2].toISOString(), "2026-10-24T10:05:00.000Z");
  state = await h.readState();
  assert.equal(state.lastRunAt, "2026-10-24T12:07:00.000Z");
  assert.ok(state.notifiedKeys.some((key) => key.includes("SHA256:intruder")));
});

test("if the first summary is not delivered, current findings are reported later", async (t) => {
  const h = await harness(t);
  h.notifyResult = { ok: false, error: "timeout" };
  await h.run();
  const state = await h.readState();
  assert.deepEqual(state.notifiedKeys, []);
  assert.equal(state.lastRunAt, "2026-10-24T10:07:00.000Z");

  h.advance(HOUR);
  h.notifyResult = { ok: true };
  await h.run();
  assert.equal(h.sent.length, 2);
  assert.match(h.sent[1], /\[MEDIUM\] Открыт порт удалённого доступа: SSH/);
});

test("--reset-baseline re-learns the baseline without notifying", async (t) => {
  const h = await harness(t);
  await h.run();
  const before = await h.readState();
  h.advance(HOUR);
  h.snapshot.accessKeys.push(intruderKey);
  assert.equal(await h.run(["--reset-baseline"]), 0);
  assert.equal(h.sent.length, 1);
  assert.equal(h.saves, 2);
  assert.deepEqual(h.stored.accessKeys, ["root|SHA256:intruder", "root|SHA256:owner"]);
  assert.ok(h.output.some((line) => line.includes("эталон переобучен")));
  assert.deepEqual(await h.readState(), before);

  h.advance(HOUR);
  await h.run();
  assert.equal(h.sent.length, 1, "the accepted key is no longer a change");
});

test("without a notify command alerts are printed and count as reported", async (t) => {
  const h = await harness(t, { realNotify: true });
  await h.run();
  h.advance(HOUR);
  h.snapshot.accessKeys.push(intruderKey);
  await h.run();
  assert.ok(h.output.some((line) => line.includes("[HIGH] Добавлен новый SSH-ключ доступа")));
  const state = await h.readState();
  assert.equal(state.lastRunAt, "2026-10-24T11:07:00.000Z");
  assert.ok(state.notifiedKeys.some((key) => key.includes("SHA256:intruder")));
});

test("notified keys are capped at 2000 while keys of present findings survive", async (t) => {
  const h = await harness(t);
  await h.run();
  const state = await h.readState();
  const sshPortKey = state.notifiedKeys[0];
  await h.writeState({ ...state, notifiedKeys: [sshPortKey, ...Array.from({ length: 2500 }, (_, i) => "old-" + i)] });
  h.advance(HOUR);
  await h.run();
  const after = await h.readState();
  assert.equal(after.notifiedKeys.length, 2000);
  assert.equal(after.notifiedKeys.at(-1), sshPortKey);
  assert.ok(!after.notifiedKeys.includes("old-0"));
  assert.equal(h.sent.length, 1, "the open SSH port must not be re-alerted");
});

test("a corrupted state file does not crash the run", async (t) => {
  const h = await harness(t);
  await h.run();
  await fs.writeFile(path.join(h.dataDir, "state.json"), "{not json");
  h.advance(HOUR);
  assert.equal(await h.run(), 0);
  assert.ok(Array.isArray((await h.readState()).notifiedKeys));
});
