const REMOTE_PORTS = new Map([
  [22, "SSH"],
  [3389, "RDP"],
  [5900, "VNC"],
  [5985, "WinRM"],
  [5986, "WinRM HTTPS"],
]);

// A new file here changes who may become root or what every process loads.
const HIGH_RISK_AUTORUN_SCOPES = new Set(["sudoers", "boot"]);
const PASSWORD_METHODS = new Set(["password", "keyboard-interactive"]);

function isLoopback(local = "") {
  return local.startsWith("127.") || local.startsWith("[::1]") || local.startsWith("::1") ||
    local.startsWith("[::ffff:127.");
}

function splitAccessKey(key) {
  if (key && typeof key === "object") return { user: key.user ?? "unknown", fingerprint: key.fingerprint ?? "" };
  const text = String(key ?? "");
  const bar = text.indexOf("|");
  return bar >= 0
    ? { user: text.slice(0, bar), fingerprint: text.slice(bar + 1) }
    : { user: "unknown", fingerprint: text };
}

function accountDetail(account) {
  return [account.user ?? "unknown", "uid " + (account.uid ?? "?"), account.shell || "/bin/sh"].join(" · ");
}

function loginDetail(login) {
  return [
    (login.user ?? "unknown") + " ← " + (login.ip ?? "?"),
    login.method,
    login.fingerprint,
    login.time,
  ].filter(Boolean).join(" · ");
}

function loginRule(login, trustedKeys) {
  if (PASSWORD_METHODS.has(login.method)) {
    return { level: "high", type: "ssh-password-login", title: "Вход на сервер по паролю" };
  }
  if (login.method === "publickey") {
    if (!trustedKeys.size) return { level: "low", type: "ssh-login", title: "Вход по SSH" };
    if (trustedKeys.has(login.fingerprint)) return null;
    return { level: "high", type: "ssh-untrusted-key-login", title: "Вход по ключу не из доверенных" };
  }
  // none (empty password), hostbased, gssapi-with-mic...: nothing the owner vouched for.
  return { level: "high", type: "ssh-other-login", title: "Вход по SSH без ключа: " + (login.method || "unknown") };
}

// options.trustedKeys: SSH key fingerprints ("SHA256:...") whose logins are expected.
export function assess(snapshot, changes = {}, options = {}) {
  const findings = [];
  const trustedKeys = new Set((options.trustedKeys ?? []).map((key) => String(key).trim()).filter(Boolean));

  for (const session of snapshot.remoteSessions ?? []) {
    findings.push({
      level: "high",
      type: "remote-session",
      title: "Обнаружена удалённая пользовательская сессия",
      detail: session.remoteHost ? session.user + " ← " + session.remoteHost : session.raw,
      evidence: session,
    });
  }

  for (const tool of snapshot.remoteTools ?? []) {
    const signature = tool.signature?.signed
      ? "подпись: " + (tool.signature.authority || tool.signature.teamIdentifier || "есть")
      : "подпись не подтверждена";
    findings.push({
      level: "medium",
      type: "remote-tool",
      title: "Запущен инструмент удалённого доступа",
      detail: (tool.process ?? "unknown") + " · PID " + (tool.pid ?? "?") + " · " + signature,
      evidence: tool,
    });
  }

  for (const socket of snapshot.listening ?? []) {
    const service = REMOTE_PORTS.get(Number(socket.localPort));
    if (!service) continue;
    findings.push({
      level: "medium",
      type: "remote-port",
      title: "Открыт порт удалённого доступа: " + service,
      detail: (socket.process ?? "unknown") + " · " + (socket.local ?? socket.endpoint),
      evidence: socket,
    });
  }

  for (const item of changes.newAutoruns ?? []) {
    findings.push({
      level: HIGH_RISK_AUTORUN_SCOPES.has(item.scope) ? "high" : "medium",
      type: "new-autorun",
      title: "Новый элемент автозапуска",
      detail: (item.name ?? "unknown") + " · " + (item.scope ?? "system"),
      evidence: item,
    });
  }

  for (const socket of changes.newListeners ?? []) {
    const local = socket.local ?? socket.endpoint ?? "";
    findings.push({
      level: isLoopback(local) ? "low" : "medium",
      type: "new-listener",
      title: "Новый listening-порт после обучения",
      detail: (socket.process ?? "unknown") + " · " + local,
      evidence: socket,
    });
  }

  for (const key of changes.newAccessKeys ?? []) {
    findings.push({
      level: "high",
      type: "new-access-key",
      title: "Добавлен новый SSH-ключ доступа",
      detail: [key.user ?? "unknown", key.fingerprint, key.comment].filter(Boolean).join(" · "),
      evidence: key,
    });
  }

  for (const key of changes.removedAccessKeys ?? []) {
    const evidence = splitAccessKey(key);
    findings.push({
      level: "low",
      type: "removed-access-key",
      title: "Удалён SSH-ключ доступа",
      detail: [evidence.user, evidence.fingerprint].filter(Boolean).join(" · "),
      evidence,
    });
  }

  for (const account of changes.newAccounts ?? []) {
    findings.push({
      level: "high",
      type: "new-account",
      title: "Новая учётная запись с входом",
      detail: accountDetail(account),
      evidence: account,
    });
  }

  for (const account of snapshot.accounts ?? []) {
    if (Number(account.uid) !== 0 || account.user === "root") continue;
    findings.push({
      level: "high",
      type: "uid0-account",
      title: "Учётная запись с правами root: " + account.user,
      detail: accountDetail(account),
      evidence: account,
    });
  }

  for (const login of snapshot.sshLogins ?? []) {
    const rule = loginRule(login, trustedKeys);
    if (rule) findings.push({ ...rule, detail: loginDetail(login), evidence: login });
  }

  const high = findings.filter((f) => f.level === "high").length;
  const medium = findings.filter((f) => f.level === "medium").length;
  const low = findings.filter((f) => f.level === "low").length;
  const status = high > 0 ? "danger" : medium > 0 ? "attention" : "ok";
  return { status, findings, counts: { high, medium, low, total: findings.length } };
}

// An open remote-access port is the same fact after its daemon restarts, so its
// key ignores the pid; otherwise every reboot would repeat the alert.
export function eventKey(finding) {
  return JSON.stringify([
    finding.type,
    finding.type === "remote-port" ? null : finding.evidence?.pid ?? null,
    finding.evidence?.remoteHost ?? null,
    finding.evidence?.path ?? null,
    finding.evidence?.local ?? null,
    finding.detail ?? null,
    // Appended for Linux findings: one key per SSH login and per file version.
    finding.evidence?.fingerprint ?? null,
    finding.evidence?.time ?? null,
    finding.evidence?.hash ?? null,
  ]);
}
