import test from "node:test";
import assert from "node:assert/strict";
import { fingerprint, compareBaseline } from "../src/baseline.js";

test("fingerprint is stable and sorted", () => {
  const value = fingerprint({
    listening: [
      { process: "b", localPort: 2, local: "*:2" },
      { process: "a", localPort: 1, local: "*:1" },
    ],
    autoruns: [
      { path: "/z" },
      { path: "/a" },
    ],
  });
  assert.deepEqual(value.listeners, ["a|1|*:1", "b|2|*:2"]);
  assert.deepEqual(value.autoruns, ["/a", "/z"]);
});

test("compareBaseline detects new listeners and autoruns", () => {
  const snapshot = {
    listening: [
      { process: "base", localPort: 80, local: "*:80" },
      { process: "new", localPort: 9000, local: "127.0.0.1:9000" },
    ],
    autoruns: [
      { name: "base.plist", path: "/base.plist" },
      { name: "new.plist", path: "/new.plist" },
    ],
  };
  const baseline = {
    createdAt: "2026-01-01T00:00:00Z",
    listeners: ["base|80|*:80"],
    autoruns: ["/base.plist"],
  };
  const result = compareBaseline(snapshot, baseline);
  assert.equal(result.ready, true);
  assert.equal(result.newListeners.length, 1);
  assert.equal(result.newAutoruns.length, 1);
  assert.equal(result.newListeners[0].process, "new");
});

test("fingerprint adds sorted access keys and accounts", () => {
  const value = fingerprint({
    accessKeys: [
      { user: "root", file: "/root/.ssh/authorized_keys", fingerprint: "SHA256:b", comment: "owner", type: "ED25519" },
      { user: "deploy", file: "/home/deploy/.ssh/authorized_keys", fingerprint: "SHA256:a", comment: "", type: "RSA" },
    ],
    accounts: [
      { user: "root", uid: 0, shell: "/bin/bash" },
      { user: "deploy", uid: 1001, shell: "/bin/sh" },
    ],
  });
  assert.deepEqual(value.accessKeys, ["deploy|SHA256:a", "root|SHA256:b"]);
  assert.deepEqual(value.accounts, ["deploy|1001|/bin/sh", "root|0|/bin/bash"]);
  assert.deepEqual(value.listeners, []);
  assert.deepEqual(value.autoruns, []);
});

test("autorun keys carry the content hash only when the collector provides one", () => {
  const value = fingerprint({
    autoruns: [
      { scope: "sudoers", name: "sudoers", path: "/etc/sudoers", hash: "0123456789abcdef" },
      { scope: "user", name: "x.plist", path: "/Library/LaunchAgents/x.plist" },
      { scope: "startup", name: "Updater" },
    ],
  });
  assert.deepEqual(value.autoruns, ["/Library/LaunchAgents/x.plist", "/etc/sudoers#0123456789abcdef", "startup|Updater"]);
});

test("compareBaseline reports edited autoruns, new or removed SSH keys and accounts", () => {
  const baseline = {
    createdAt: "2026-10-23T00:00:00Z",
    listeners: [],
    autoruns: ["/etc/sudoers#aaaaaaaaaaaaaaaa", "/etc/cron.d/old#cccccccccccccccc"],
    accessKeys: ["root|SHA256:owner", "root|SHA256:gone"],
    accounts: ["root|0|/bin/bash", "olduser|1002|/bin/bash"],
  };
  const snapshot = {
    listening: [],
    autoruns: [{ scope: "sudoers", name: "sudoers", path: "/etc/sudoers", hash: "bbbbbbbbbbbbbbbb" }],
    accessKeys: [
      { user: "root", fingerprint: "SHA256:owner", comment: "owner@laptop" },
      { user: "root", fingerprint: "SHA256:intruder", comment: "x" },
    ],
    accounts: [
      { user: "root", uid: 0, shell: "/bin/bash" },
      { user: "backdoor", uid: 0, shell: "/bin/sh" },
    ],
  };
  const result = compareBaseline(snapshot, baseline);
  assert.equal(result.ready, true);
  assert.deepEqual(result.newAutoruns.map((item) => item.path), ["/etc/sudoers"]);
  assert.deepEqual(result.removedAutoruns, ["/etc/sudoers#aaaaaaaaaaaaaaaa", "/etc/cron.d/old#cccccccccccccccc"]);
  assert.deepEqual(result.newAccessKeys.map((key) => key.fingerprint), ["SHA256:intruder"]);
  assert.deepEqual(result.removedAccessKeys, ["root|SHA256:gone"]);
  assert.deepEqual(result.newAccounts, [{ user: "backdoor", uid: 0, shell: "/bin/sh" }]);
  assert.deepEqual(result.removedAccounts, ["olduser|1002|/bin/bash"]);
});

test("compareBaseline treats keys and accounts as not learned in an old baseline", () => {
  const oldBaseline = {
    createdAt: "2026-09-01T00:00:00Z",
    listeners: ["sshd|22|*:22"],
    autoruns: ["/Library/LaunchAgents/a.plist"],
  };
  const snapshot = {
    listening: [{ process: "sshd", localPort: 22, local: "*:22" }],
    autoruns: [{ name: "a.plist", path: "/Library/LaunchAgents/a.plist" }],
    accessKeys: [{ user: "root", fingerprint: "SHA256:any" }],
    accounts: [{ user: "root", uid: 0, shell: "/bin/bash" }],
  };
  const result = compareBaseline(snapshot, oldBaseline);
  assert.equal(result.ready, true);
  for (const key of [
    "newListeners", "newAutoruns", "removedListeners", "removedAutoruns",
    "newAccessKeys", "removedAccessKeys", "newAccounts", "removedAccounts",
  ]) {
    assert.deepEqual(result[key], [], key);
  }
});

test("compareBaseline without a baseline returns empty change lists", () => {
  const result = compareBaseline({ accessKeys: [{ user: "root", fingerprint: "SHA256:x" }] }, null);
  assert.equal(result.ready, false);
  for (const key of ["newAccessKeys", "removedAccessKeys", "newAccounts", "removedAccounts"]) {
    assert.deepEqual(result[key], [], key);
  }
});
