import { spawn } from "node:child_process";

export const NOTIFY_TIMEOUT_MS = 20000;

// Delivers a message through the owner's own command (TASHEV_GUARD_NOTIFY_CMD):
// it runs via /bin/sh -c and receives the message on stdin, so it can forward
// it to Telegram, MAX, email or anything else. Returns { ok }; without a
// configured command it returns { ok: true, skipped: true }.
// The command's stdout is discarded; its stderr goes to our stderr (the log),
// so delivery errors stay visible.
export function notifyCommand(message, options = {}) {
  const env = options.env ?? process.env;
  const command = options.command ?? env.TASHEV_GUARD_NOTIFY_CMD;
  const timeoutMs = options.timeoutMs ?? NOTIFY_TIMEOUT_MS;
  if (!command || !String(command).trim()) return Promise.resolve({ ok: true, skipped: true });

  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    let child;
    try {
      // detached: the command gets its own process group, so a timeout can
      // stop everything it started, not just the shell.
      child = spawn("/bin/sh", ["-c", String(command)], {
        env,
        stdio: ["pipe", "ignore", "inherit"],
        detached: true,
      });
    } catch (error) {
      finish({ ok: false, error: error.code || error.message });
      return;
    }

    child.on("error", (error) => finish({ ok: false, error: error.code || error.message }));
    child.on("exit", (code, signal) => finish(code === 0 ? { ok: true, code } : { ok: false, code, signal }));
    timer = setTimeout(() => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
      finish({ ok: false, error: "timeout" });
    }, timeoutMs);

    child.stdin.on("error", () => {}); // EPIPE when the command does not read stdin
    child.stdin.end(String(message) + "\n");
  });
}
