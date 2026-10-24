import test from "node:test";
import assert from "node:assert/strict";
import { assess, eventKey } from "../src/risk.js";
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

test("an open remote-access port keeps one event key when the daemon restarts with a new pid", () => {
  const before = assess({ listening: [{ localPort: 22, process: "sshd", local: "0.0.0.0:22", pid: 100 }] });
  const after = assess({ listening: [{ localPort: 22, process: "sshd", local: "0.0.0.0:22", pid: 200 }] });
  assert.equal(eventKey(before.findings[0]), eventKey(after.findings[0]));
});

test("parseLsof decodes escaped UTF-8 process names", () => {
  const rows = parseLsof("p7\nc\\xD0\\xA2\\xD0\\xB5\\xD1\\x81\\xD1\\x82\nn127.0.0.1:9001\nTST=LISTEN\n");
  assert.equal(rows[0].process, "Тест");
});

const ownerLogin = {
  time: "2026-10-23T21:24:59.000Z", user: "root", method: "publickey", ip: "1.2.3.4", port: 5555,
  keyType: "ED25519", fingerprint: "SHA256:owner",
};
const strangerLogin = {
  time: "2026-10-23T21:29:00.000Z", user: "root", method: "publickey", ip: "6.6.6.6", port: 2222,
  keyType: "RSA", fingerprint: "SHA256:stranger",
};

test("a new SSH access key is high risk, a removed one is low", () => {
  const result = assess({}, {
    newAccessKeys: [{
      user: "root", file: "/root/.ssh/authorized_keys", bits: 256,
      fingerprint: "SHA256:intruder", comment: "evil@box; temp", type: "ED25519",
    }],
    removedAccessKeys: ["deploy|SHA256:old"],
  });
  const added = result.findings.find((f) => f.type === "new-access-key");
  assert.equal(added.level, "high");
  assert.equal(added.title, "Добавлен новый SSH-ключ доступа");
  assert.equal(added.detail, "root · SHA256:intruder · evil@box; temp");
  const removed = result.findings.find((f) => f.type === "removed-access-key");
  assert.equal(removed.level, "low");
  assert.equal(removed.title, "Удалён SSH-ключ доступа");
  assert.equal(removed.detail, "deploy · SHA256:old");
  assert.equal(result.status, "danger");
});

test("a new login account is high risk", () => {
  const result = assess({}, { newAccounts: [{ user: "deploy2", uid: 1005, shell: "/bin/bash" }] });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
    ["new-account", "high", "Новая учётная запись с входом"],
  ]);
  assert.match(result.findings[0].detail, /deploy2/);
});

test("every uid 0 account except root is high risk, even without a baseline change", () => {
  const result = assess({
    accounts: [
      { user: "root", uid: 0, shell: "/bin/bash" },
      { user: "toor", uid: 0, shell: "/bin/sh" },
      { user: "rinat", uid: 1000, shell: "/bin/bash" },
    ],
  });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
    ["uid0-account", "high", "Учётная запись с правами root: toor"],
  ]);
});

test("password and keyboard-interactive SSH logins are high risk", () => {
  const result = assess({
    sshLogins: [
      { time: "2026-10-23T21:25:10.123Z", user: "root", method: "password", ip: "2001:db8::1", port: 4444, keyType: null, fingerprint: null },
      { time: "2026-10-23T21:26:00.000Z", user: "bob", method: "keyboard-interactive", ip: "1.2.3.4", port: 1, keyType: null, fingerprint: null },
    ],
  }, {}, { trustedKeys: ["SHA256:owner"] });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
    ["ssh-password-login", "high", "Вход на сервер по паролю"],
    ["ssh-password-login", "high", "Вход на сервер по паролю"],
  ]);
  assert.equal(result.findings[0].detail, "root ← 2001:db8::1 · password · 2026-10-23T21:25:10.123Z");
});

test("key logins: trusted key is silent, an untrusted key is high risk", () => {
  const result = assess({ sshLogins: [ownerLogin, strangerLogin] }, {}, { trustedKeys: ["SHA256:other", "SHA256:owner"] });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
    ["ssh-untrusted-key-login", "high", "Вход по ключу не из доверенных"],
  ]);
  assert.equal(result.findings[0].detail, "root ← 6.6.6.6 · publickey · SHA256:stranger · 2026-10-23T21:29:00.000Z");
  assert.equal(result.findings[0].evidence.ip, "6.6.6.6");
  assert.equal(result.findings[0].evidence.time, strangerLogin.time);
  assert.equal(result.findings[0].evidence.fingerprint, "SHA256:stranger");
});

test("key logins without a trusted list are low-level notes", () => {
  for (const options of [{ trustedKeys: [] }, undefined]) {
    const result = assess({ sshLogins: [ownerLogin, strangerLogin] }, {}, options);
    assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
      ["ssh-login", "low", "Вход по SSH"],
      ["ssh-login", "low", "Вход по SSH"],
    ]);
    assert.equal(result.status, "ok");
  }
});

test("SSH logins with other methods (none, hostbased) are high risk", () => {
  const result = assess({
    sshLogins: [
      { ...ownerLogin, method: "none", keyType: null, fingerprint: null },
      { ...ownerLogin, method: "hostbased", keyType: null, fingerprint: null },
    ],
  }, {}, { trustedKeys: ["SHA256:owner"] });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level]), [
    ["ssh-other-login", "high"],
    ["ssh-other-login", "high"],
  ]);
  assert.match(result.findings[0].title, /none/);
});

test("new sudoers and boot autoruns are high, other new autoruns stay medium", () => {
  const result = assess({}, {
    newAutoruns: [
      { scope: "sudoers", name: "sudoers.d/99-backdoor", path: "/etc/sudoers.d/99-backdoor", hash: "1111111111111111" },
      { scope: "boot", name: "ld.so.preload", path: "/etc/ld.so.preload", hash: "2222222222222222" },
      { scope: "cron", name: "cron.d/job", path: "/etc/cron.d/job", hash: "3333333333333333" },
      { scope: "systemd", name: "evil.service", path: "/etc/systemd/system/evil.service", hash: "4444444444444444" },
      { scope: "user", name: "x.plist", path: "/Users/a/Library/LaunchAgents/x.plist" },
    ],
  });
  assert.deepEqual(result.findings.map((f) => [f.type, f.level, f.title]), [
    ["new-autorun", "high", "Новый элемент автозапуска"],
    ["new-autorun", "high", "Новый элемент автозапуска"],
    ["new-autorun", "medium", "Новый элемент автозапуска"],
    ["new-autorun", "medium", "Новый элемент автозапуска"],
    ["new-autorun", "medium", "Новый элемент автозапуска"],
  ]);
});

test("IPv4-mapped loopback listeners are low risk like plain loopback", () => {
  const result = assess({}, { newListeners: [{ process: "node", localPort: 8080, local: "[::ffff:127.0.0.1]:8080" }] });
  assert.equal(result.findings[0].level, "low");
});

test("eventKey separates logins by time and key, autorun edits by hash, and keeps old fields first", () => {
  const login = { time: "2026-10-23T21:24:59.000Z", user: "root", method: "password", ip: "1.2.3.4", port: 1, keyType: null, fingerprint: null };
  const [first, second] = assess({ sshLogins: [login, { ...login, time: "2026-10-23T22:24:59.000Z" }] }).findings;
  assert.notEqual(eventKey(first), eventKey(second));

  const same = (evidence) => ({ type: "ssh-untrusted-key-login", detail: "same detail", evidence });
  const keys = new Set([
    eventKey(same({ fingerprint: "SHA256:a", time: "t1" })),
    eventKey(same({ fingerprint: "SHA256:b", time: "t1" })),
    eventKey(same({ fingerprint: "SHA256:a", time: "t2" })),
  ]);
  assert.equal(keys.size, 3);

  const edit = (hash) => ({ type: "new-autorun", detail: "sudoers · sudoers", evidence: { path: "/etc/sudoers", hash } });
  assert.notEqual(eventKey(edit("1111111111111111")), eventKey(edit("2222222222222222")));

  const legacy = { type: "remote-tool", detail: "AnyDesk · PID 7", evidence: { pid: 7, path: "/opt/anydesk", local: "*:7070" } };
  assert.deepEqual(JSON.parse(eventKey(legacy)).slice(0, 6), ["remote-tool", 7, null, "/opt/anydesk", "*:7070", "AnyDesk · PID 7"]);
});
