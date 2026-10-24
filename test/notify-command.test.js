import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { notifyCommand } from "../src/notify-command.js";

const shOnly = { skip: process.platform === "win32" ? "needs /bin/sh" : false };

test("notifyCommand succeeds when the command exits 0", shOnly, async () => {
  const result = await notifyCommand("Tashev Guard · web-1\n[HIGH] test", { command: "cat >/dev/null" });
  assert.equal(result.ok, true);
});

test("notifyCommand fails when the command exits non-zero", shOnly, async () => {
  const result = await notifyCommand("message", { command: "exit 1" });
  assert.equal(result.ok, false);
  assert.equal(result.code, 1);
});

test("notifyCommand passes the message to the command on stdin", shOnly, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "tashev-guard-notify-"));
  const out = path.join(dir, "message.txt");
  try {
    const message = "Tashev Guard · web-1\n[HIGH] Добавлен новый SSH-ключ доступа — root · SHA256:x";
    const result = await notifyCommand(message, {
      command: 'cat > "$NOTIFY_OUT"',
      env: { ...process.env, NOTIFY_OUT: out },
    });
    assert.equal(result.ok, true);
    assert.equal(await fs.readFile(out, "utf8"), message + "\n");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("notifyCommand survives a command that ignores stdin", shOnly, async () => {
  const result = await notifyCommand("x".repeat(1024 * 1024), { command: "exit 0" });
  assert.equal(result.ok, true);
});

test("notifyCommand gives up after the timeout", shOnly, async () => {
  const started = Date.now();
  const result = await notifyCommand("message", { command: "sleep 5", timeoutMs: 200 });
  assert.equal(result.ok, false);
  assert.equal(result.error, "timeout");
  assert.ok(Date.now() - started < 3000, "took " + (Date.now() - started) + " ms");
});

test("notifyCommand without a configured command skips delivery", async () => {
  assert.deepEqual(await notifyCommand("message", { command: "" }), { ok: true, skipped: true });
  assert.deepEqual(await notifyCommand("message", { env: {} }), { ok: true, skipped: true });
});
