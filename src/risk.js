const REMOTE_PORTS = new Map([
  [22, "SSH"],
  [3389, "RDP"],
  [5900, "VNC"],
  [5985, "WinRM"],
  [5986, "WinRM HTTPS"],
]);

function isLoopback(local = "") {
  return local.startsWith("127.") || local.startsWith("[::1]") || local.startsWith("::1");
}

export function assess(snapshot, baseline = {}) {
  const findings = [];

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

  for (const item of baseline.newAutoruns ?? []) {
    findings.push({
      level: "medium",
      type: "new-autorun",
      title: "Новый элемент автозапуска",
      detail: (item.name ?? "unknown") + " · " + (item.scope ?? "system"),
      evidence: item,
    });
  }

  for (const socket of baseline.newListeners ?? []) {
    const local = socket.local ?? socket.endpoint ?? "";
    findings.push({
      level: isLoopback(local) ? "low" : "medium",
      type: "new-listener",
      title: "Новый listening-порт после обучения",
      detail: (socket.process ?? "unknown") + " · " + local,
      evidence: socket,
    });
  }

  const high = findings.filter((f) => f.level === "high").length;
  const medium = findings.filter((f) => f.level === "medium").length;
  const low = findings.filter((f) => f.level === "low").length;
  const status = high > 0 ? "danger" : medium > 0 ? "attention" : "ok";
  return { status, findings, counts: { high, medium, low, total: findings.length } };
}

export function eventKey(finding) {
  return JSON.stringify([
    finding.type,
    finding.evidence?.pid ?? null,
    finding.evidence?.remoteHost ?? null,
    finding.evidence?.path ?? null,
    finding.evidence?.local ?? null,
    finding.detail ?? null,
  ]);
}
