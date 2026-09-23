import test from "node:test";
import assert from "node:assert/strict";
import { assess } from "../src/risk.js";
import { parseLsof } from "../src/collectors/macos.js";

test("parseLsof extracts process, endpoint and state", () => {
  const rows = parseLsof("p42\ncssh\nn127.0.0.1:22\nTST=LISTEN\n");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].pid, 42);
  assert.equal(rows[0].process, "ssh");
  assert.equal(rows[0].state, "LISTEN");
});

test("remote session is high risk", () => {
  const result = assess({ remoteSessions: [{ user: "sam", remoteHost: "10.0.0.8" }], remoteTools: [], listening: [] });
  assert.equal(result.status, "danger");
  assert.equal(result.counts.high, 1);
});

test("remote port is attention, not proof of compromise", () => {
  const result = assess({ remoteSessions: [], remoteTools: [], listening: [{ localPort: 22, process: "sshd", local: "*:22" }] });
  assert.equal(result.status, "attention");
  assert.match(result.findings[0].title, /SSH/);
});

test("parseLsof decodes escaped UTF-8 process names", () => {
  const rows = parseLsof("p7\nc\\xD0\\xA2\\xD0\\xB5\\xD1\\x81\\xD1\\x82\nn127.0.0.1:9001\nTST=LISTEN\n");
  assert.equal(rows[0].process, "Тест");
});
