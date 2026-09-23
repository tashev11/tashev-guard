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
